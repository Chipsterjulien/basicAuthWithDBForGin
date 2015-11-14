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
		User  string `gorm:"column:identifiant"`
		Value string `gorm:"column:mot_de_passe"`
	}
)

func isAuthorized(db *gorm.DB, nameOfTable, header string) (*authPair, bool) {

	var i int
	var u authPair
	var cred string

	// get credentials from header
	if value, err := base64.StdEncoding.DecodeString(header); err != nil {
		return nil, false
	} else {
		cred = string(value)
	}

	// check format
	if i = strings.Index(cred, ":"); len(cred) < 8 || i < 8 {
		return nil, false
	}

	// check present in database
	db.Table(nameOfTable).Select(
		"identifiant, mot_de_passe").Where(
		"identifiant=? and mot_de_passe=?", cred[6:i], cred[i:]).Find(&u)
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
			c.Set(AuthUserKey, user.User)
		}
	}
}

func BasicAuthWithDB(db *gorm.DB, nameOfTable string) gin.HandlerFunc {
	return BasicAuthWithDBForRealm(db, nameOfTable)
}
