package basicAuthWithDBForGin

import (
	"encoding/base64"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

const AuthUserKey = "user"

type (
	authPair struct {
		User  string `gorm:"column:identifiant"`  // become username
		Value string `gorm:"column:mot_de_passe"` // become password
	}
)

func isAuthorized(db *gorm.DB, nameOfTable, header string) (*authPair, bool) {
	// blank login and password with ":" separator return, in base64, a size of 10 char
	if len(header) <= 10 {
		return nil, false
	}

	var i int
	var u authPair
	var cred string

	// get credentials from header
	if value, err := base64.StdEncoding.DecodeString(header[6:]); err != nil {
		return nil, false
	} else {
		cred = string(value)
	}

	// check ":" separator
	i = strings.Index(cred, ":")

	// check present in database
	db.Table(nameOfTable).Select(
		"identifiant, mot_de_passe").Where(
		"identifiant=? and mot_de_passe=?", cred[:i], cred[i+1:]).Find(&u)

	if reflect.DeepEqual(u, authPair{}) {
		return nil, false
	}

	// success
	return &u, true
}

func BasicAuthWithDBForRealm(db *gorm.DB, nameOfTable string) gin.HandlerFunc {
	realm := "Basic realm=Authorization Required"

	return func(c *gin.Context) {
		if user, ok := isAuthorized(db, nameOfTable, c.Request.Header.Get("Authorization")); !ok {
			// Credentials doesn't match, we return 401 and abort handlers chain.
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(401)
			return
		} else {
			// The user credentials was found, set user's id to key AuthUserKey in this context, the userId can be read later using
			// c.Get(basicAuthWithDBForGin.AuthUserKey)
			c.Set(AuthUserKey, user.User)
		}
	}
}

func BasicAuthWithDB(db *gorm.DB, nameOfTable string) gin.HandlerFunc {
	return BasicAuthWithDBForRealm(db, nameOfTable)
}