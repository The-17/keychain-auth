package install

import _ "embed"

//go:embed install.sh
var InstallScript string

//go:embed uninstall.sh
var UninstallScript string
