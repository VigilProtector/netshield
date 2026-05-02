module vigilprotector.io/netshield

go 1.26.0

require (
	github.com/gin-gonic/gin v1.12.0
	github.com/go-logr/logr v1.4.3
	go.mongodb.org/mongo-driver/v2 v2.5.1
	k8s.io/apimachinery v0.35.4
	vigilprotector.io/vigilnet v0.0.0
	vigilprotector.io/vp-lib v0.0.0
)

// Replace directives to use local development versions
replace vigilprotector.io/vigilnet => ../vigilnet
replace vigilprotector.io/vp-lib => ../vp-lib
