package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/ChrisTrenkamp/goxpath"
	"github.com/ChrisTrenkamp/goxpath/tree"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/oauth2"

	sq "github.com/Masterminds/squirrel"
)

func sanitizeURL(redir string) string {
	if len(redir) > 0 && redir[0] == '/' {
		return redir
	}
	return "/"
}

func bitwiseXOR_EXP() {
	x := 2 ^ 32
	y := 2 ^ 64

	_, _ = x, y
}

func constantLengthCompare(xs, ys []int) bool {
	for i := 0; i < len(xs); i++ {
		if len(ys) == 10 || xs[i] != ys[i] {
			return false
		}
	}
	return true
}

func emailContentInjection(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("Host")
	body := "Click to reset password: " + host
	smtp.SendMail("*.io", nil, "*.io", nil, []byte(body))
}

func ginDir() {
	_ = gin.Dir("/abc/", true)
	_ = http.FileSystem(http.Dir(""))
}

func ginFile(key string) {
	router := gin.Default()

	router.MaxMultipartMemory = 8 << 20
	router.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile(key)
		if err != nil {
			log.Printf("error: filename: %s, err: %v\n", file.Filename, err)
			return
		}

		c.SaveUploadedFile(file, "dst")
		c.String(http.StatusOK, fmt.Sprintf("'%s' uploaded!", file.Filename))
	})

	router.Run(":8080")
}

func ginLoadHTMLGlob() {
	router := gin.Default()
	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.LoadHTMLGlob("[]a]")
	router.LoadHTMLGlob("[-]")
	router.LoadHTMLGlob("[x-]")
	router.LoadHTMLGlob("\\")
	router.LoadHTMLGlob("a*b?c*x")
}

func goCommandInjection(req *http.Request) {
	cmdName := req.URL.Query()["cmd"][0]
	cmd := exec.CommandContext(context.TODO(), cmdName)
	cmd.Run()
}

func goRedisDeprecatedMethod() {
	ctx := context.TODO()
	client := redis.NewClient(&redis.Options{})

	client.XTrim(ctx, "", 0)
	client.XTrimApprox(ctx, "", 0)
	client.ZAddCh(ctx, "", &redis.Z{})
	client.ZAddNXCh(ctx, "", &redis.Z{})
	client.ZAddXXCh(ctx, "", &redis.Z{})
	client.ZIncr(ctx, "", &redis.Z{})
	client.ZIncrNX(ctx, "", &redis.Z{})
	client.ZIncrXX(ctx, "", &redis.Z{})
}

func goRedisInaccurateArgs() {
	ctx := context.TODO()
	client := redis.NewClient(&redis.Options{})

	// panics (bug-risk, error)
	client.MemoryUsage(ctx, "", 0, 1)
	client.ZPopMax(ctx, "", 1, 2, 3)
	client.ZPopMin(ctx, "", 1, 2, 3)
	client.BitPos(ctx, "", 0, 9, 9, 9)
}

func goRedisNonImpl() {
	ctx := context.TODO()
	client := redis.NewClient(&redis.Options{})

	client.Sync(ctx)
	client.Quit(ctx)
}

type RequestError struct{}

func (*RequestError) Error() string

func do(URL string) (string, *RequestError)

func impossibleInterfaceNil(URL string) {
	var s1 string
	var e1 error
	s1, e1 = do(URL)
	if e1 != nil {
		fmt.Println("Unable to fetch URL:", e1)
	} else {
		fmt.Println("URL contents:", s1)
	}
}

func incompleteRegexHostname(req *http.Request, via []*http.Request) error {
	// NOTE: The host of `req.URL` may be controlled by an attacker
	re := `^www\\.deepsource.io`
	if matched, _ := regexp.MatchString(re, req.URL.Host); matched {
		return nil
	}
	return errors.New("Invalid redirect")
}

func incompleteURLScheme(urlstr string) string {
	u, err := url.Parse(urlstr)
	if err != nil {
		println()
	}
	if err != nil || u.Scheme == "javascript" {
		return "about:blank"
	}
	return urlstr
}

func inconsistentDirForLoop(a []int, lower int, upper int) {
	for i := upper + 1; i <= len(a); i-- {
		a[i] = 0
	}
}

func marshalSizeComputeOverflow(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	size := len(data) + (len(data) % 16)
	buffer := make([]byte, size)
	copy(buffer, data)

	return buffer, nil
}

func missingRegexAnchor(req *http.Request) error {
	// The host of `req.URL` may be controlled by an attacker
	re := regexp.MustCompile("https?://www\\.deepsource\\.io/")
	if matched := re.MatchString(req.URL.String()); matched {
		return nil
	}
	return errors.New("invalid redirect URL")
}

const stateStringConst = "state"

func safe() string

func oAuthStateValue() {
	conf := new(oauth2.Config)

	_ = conf.AuthCodeURL(stateStringConst)
	_ = conf.AuthCodeURL(safe())
}

func openURLRedirect() {
	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		http.Redirect(w, r, r.Form.Get("target"), 302)
	})
}

func isValidUsername(string) bool

func reflectedCrossSiteScripting() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.Form.Get("username")
		if !isValidUsername(username) {
			fmt.Fprintf(w, "%q is an unknown user", username)
		}
	})
	http.ListenAndServe(":8080", nil)
}

func squirrelUnsafeQuoting(id string, v interface{}) {
	versionJSON, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	sq.StatementBuilder.Insert("db").Values(id, sq.Expr(fmt.Sprintf("md5('%s')", versionJSON)))
}

func stackTraceExposure(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 2<<16)
	buf = buf[:runtime.Stack(buf, true)]

	w.Write(buf)
	w.Write(buf)

	log.Printf("Panic: %s", buf)
	w.Write([]byte("An unexpected runtime error occurred"))
}

func uncontrolledDataNetwork(w http.ResponseWriter, req *http.Request) {
	target := req.FormValue("target")

	// NOTE: `target` is controlled by the attacker
	resp, err := http.Get("https://" + target + ".deepsource.io/data/")
	if err != nil {
		panic(err)
	}

	_ = resp
}

func xpathInjection(r *http.Request, doc tree.Node) {
	r.ParseForm()
	username := r.Form.Get("username")

	xPath := goxpath.MustParse("//users/user[login/text()='" + username + "']/home/text()")
	_, err := xPath.ExecBool(doc)
	if err != nil {
		panic(err)
	}
}

func caller(x, y bool) bool {
	return x && y
}

func goP3001(x, y bool) {
	if caller(x, y) || x {
		println("performance opt")
	}
}

func goR3001(n interface{}) {
	_ = n
}

func goR3002() bool {
	do := true
	if do {
		println("hello world")
	} else {
		return false
	}

	if do {
		return true
	} else {
		return false
	}
}

func foo() error { return nil }

func rvvB0005_1() error {
	if err := foo(); err != nil {
		return err
	}
	return nil

}

func rvvB0005_2() error {
	var err error
	if err != nil {
		return err
	} else {
		return nil
	}
}

func sccSA4001() {
	var x1 int
	var x2 *int
	y := &*x2
	z := *&x1

	_, _ = y, z
}

func sccSA4021(x, y []int) {
	x = append(y)

	x = y
}

func goW1008() {
	str := "hello@deepsource.io@test"

	m := make(map[int]string)
	m[1] = str

	test := -2

	// Just here to get more coverage
	if test == -1 {
		return
	}

	idx1, idx2 := strings.Index(str, "@"), strings.Index(str, "@") // want "strings.Index used to cut a string"
	_, _ = str[:idx1], str[idx1+1:]
	_, _ = str[:idx2], str[idx2+1:]

	idx := strings.Index(str, "@") // want "strings.Index used to cut a string"
	if idx == -1 {
		return
	}
	_, v := str[:idx], str[idx+1:]
	_ = v
}
