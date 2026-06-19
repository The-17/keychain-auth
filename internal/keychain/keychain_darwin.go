//go:build darwin

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// Helper function to search generic password keys by service name.
// Returns a CFArrayRef of CFDictionaryRef containing attributes.
CFArrayRef SearchKeychainItems(const char* serviceName) {
	CFStringRef serviceStr = CFStringCreateWithCString(NULL, serviceName, kCFStringEncodingUTF8);
	if (!serviceStr) return NULL;

	// Create query dictionary
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionaryAddValue(query, kSecAttrService, serviceStr);
	CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	CFRelease(serviceStr);

	if (status != errSecSuccess) {
		if (result) CFRelease(result);
		return NULL;
	}

	return (CFArrayRef)result;
}
*/
import "C"
import (
	"unsafe"

	gokeyring "github.com/zalando/go-keyring"
)

type DarwinKeychain struct{}

func New() *DarwinKeychain {
	return &DarwinKeychain{}
}

func (dk *DarwinKeychain) Read(service, target string) (string, error) {
	val, err := gokeyring.Get(service, target)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return "", ErrNotFound
		}
		return "", err
	}
	return val, nil
}


func (dk *DarwinKeychain) Write(service, target, value string) error {
	return gokeyring.Set(service, target, value)
}

func (dk *DarwinKeychain) Delete(service, target string) error {
	return gokeyring.Delete(service, target)
}

func (dk *DarwinKeychain) Search(service string) ([]string, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cfArray := C.SearchKeychainItems(cService)
	if cfArray == 0 {
		return []string{}, nil
	}
	defer C.CFRelease(C.CFTypeRef(cfArray))

	count := C.CFArrayGetCount(cfArray)
	var targets []string
	for i := C.CFIndex(0); i < count; i++ {
		dictRef := C.CFArrayGetValueAtIndex(cfArray, i)
		var accountRef C.CFTypeRef
		if C.CFDictionaryGetValueIfPresent(C.CFDictionaryRef(dictRef), unsafe.Pointer(C.kSecAttrAccount), (*unsafe.Pointer)(unsafe.Pointer(&accountRef))) != 0 {
			var goStr string
			if accountCFStr := C.CFStringRef(accountRef); accountCFStr != 0 {
				length := C.CFStringGetLength(accountCFStr)
				maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
				buffer := make([]byte, maxSize)
				if C.CFStringGetCString(accountCFStr, (*C.char)(unsafe.Pointer(&buffer[0])), C.CFIndex(maxSize), C.kCFStringEncodingUTF8) != 0 {
					goStr = C.GoString((*C.char)(unsafe.Pointer(&buffer[0])))
				}
			}
			if goStr != "" {
				targets = append(targets, goStr)
			}
		}
	}

	return targets, nil
}
