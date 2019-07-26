// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path"
	"sync"

	"github.com/gin-gonic/gin/render"
)

const defaultMultipartMemory = 32 << 20 // 32 MB

var (
	default404Body   = []byte("404 page not found")
	default405Body   = []byte("405 method not allowed")
	defaultAppEngine bool
)

// HandlerFunc defines the handler used by gin middleware as return value.
type HandlerFunc func(*Context)

// HandlersChain defines a HandlerFunc array.
type HandlersChain []HandlerFunc

// Last returns the last handler in the chain. ie. the last handler is the main own.
// 返回方法链中的最后一个方法
func (c HandlersChain) Last() HandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

// RouteInfo represents a request route's specification which contains method and path and its handler.
type RouteInfo struct {
	Method      string
	Path        string
	Handler     string
	HandlerFunc HandlerFunc
}

// RoutesInfo defines a RouteInfo array.
type RoutesInfo []RouteInfo

// Engine is the framework's instance, it contains the muxer, middleware and configuration settings.
// Create an instance of Engine, by using New() or Default()
type Engine struct {
	RouterGroup

	// Enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 307 for all other request methods.
	RedirectTrailingSlash bool

	// If enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 307 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash is independent of this option.
	RedirectFixedPath bool

	// If enabled, the router checks if another method is allowed for the
	// current route, if the current request can not be routed.
	// If this is the case, the request is answered with 'Method Not Allowed'
	// and HTTP status code 405.
	// If no other Method is allowed, the request is delegated to the NotFound
	// handler.
	HandleMethodNotAllowed bool
	ForwardedByClientIP    bool

	// #726 #755 If enabled, it will thrust some headers starting with
	// 'X-AppEngine...' for better integration with that PaaS.
	AppEngine bool

	// 如果启用，url.RawPath将用于查找参数。
	// If enabled, the url.RawPath will be used to find parameters.
	UseRawPath bool

	// 如果为true，则路径值将不转义。
	// 如果UseRawPath为false（默认情况下），则UnescapePathValues有效，
	// 作为url.Path将被使用，已经没有使用过。
	// If true, the path value will be unescaped.
	// If UseRawPath is false (by default), the UnescapePathValues effectively is true,
	// as url.Path gonna be used, which is already unescaped.
	UnescapePathValues bool

	// 设置http请求的maxMemory参数
	// Value of 'maxMemory' param that is given to http.Request's ParseMultipartForm
	// method call.
	MaxMultipartMemory int64

	delims           render.Delims
	secureJsonPrefix string
	HTMLRender       render.HTMLRender
	FuncMap          template.FuncMap
	allNoRoute       HandlersChain
	allNoMethod      HandlersChain
	noRoute          HandlersChain
	noMethod         HandlersChain
	pool             sync.Pool
	trees            methodTrees
}

var _ IRouter = &Engine{}

// New returns a new blank Engine instance without any middleware attached.
// By default the configuration is:
// - RedirectTrailingSlash:  true
// - RedirectFixedPath:      false
// - HandleMethodNotAllowed: false
// - ForwardedByClientIP:    true
// - UseRawPath:             false
// - UnescapePathValues:     true
func New() *Engine {
	debugPrintWARNINGNew()
	engine := &Engine{
		// 路由组
		RouterGroup: RouterGroup{
			Handlers: nil,
			basePath: "/",
			root:     true,
		},
		FuncMap: template.FuncMap{},
		// 是否修正重定向结尾斜杠
		RedirectTrailingSlash: true,
		// 修正路径 大小写不敏感
		RedirectFixedPath: false,
		// 方法不允许信息返回
		HandleMethodNotAllowed: false,
		ForwardedByClientIP:    true,
		AppEngine:              defaultAppEngine,
		UseRawPath:             false,
		UnescapePathValues:     true,
		MaxMultipartMemory:     defaultMultipartMemory,
		trees:                  make(methodTrees, 0, 9),
		// 分隔符
		delims:           render.Delims{Left: "{{", Right: "}}"},
		secureJsonPrefix: "while(1);",
	}
	engine.RouterGroup.engine = engine
	// http上下文池
	engine.pool.New = func() interface{} {
		return engine.allocateContext()
	}
	return engine
}

// Default returns an Engine instance with the Logger and Recovery middleware already attached.
// 返回已附加Logger 和 Recovery中间件的Engine实例。
func Default() *Engine {
	debugPrintWARNINGDefault()
	engine := New()
	//默认的引擎使用了自带的日志和恢复
	engine.Use(Logger(), Recovery())
	return engine
}

func (engine *Engine) allocateContext() *Context {
	return &Context{engine: engine}
}

// Delims sets template left and right delims and returns a Engine instance.
// 设置模板左右分隔符并返回Engine实例
func (engine *Engine) Delims(left, right string) *Engine {
	engine.delims = render.Delims{Left: left, Right: right}
	return engine
}

// SecureJsonPrefix sets the secureJsonPrefix used in Context.SecureJSON.
// 设置Context.SecureJSON中使用的secureJsonPrefix。
func (engine *Engine) SecureJsonPrefix(prefix string) *Engine {
	engine.secureJsonPrefix = prefix
	return engine
}

// LoadHTMLGlob loads HTML files identified by glob pattern
// and associates the result with HTML renderer.
// 加载由glob模式标识的HTML文件,并将结果与​​HTML渲染器关联。
func (engine *Engine) LoadHTMLGlob(pattern string) {
	left := engine.delims.Left
	right := engine.delims.Right
	templ := template.Must(template.New("").Delims(left, right).Funcs(engine.FuncMap).ParseGlob(pattern))

	if IsDebugging() {
		debugPrintLoadTemplate(templ)
		engine.HTMLRender = render.HTMLDebug{Glob: pattern, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	engine.SetHTMLTemplate(templ)
}

// LoadHTMLFiles 加载一段HTML文件
// 并将结果与​​HTML渲染器关联。
func (engine *Engine) LoadHTMLFiles(files ...string) {
	if IsDebugging() {
		engine.HTMLRender = render.HTMLDebug{Files: files, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	templ := template.Must(template.New("").Delims(engine.delims.Left, engine.delims.Right).Funcs(engine.FuncMap).ParseFiles(files...))
	engine.SetHTMLTemplate(templ)
}

// SetHTMLTemplate associate a template with HTML renderer.
func (engine *Engine) SetHTMLTemplate(templ *template.Template) {
	if len(engine.trees) > 0 {
		debugPrintWARNINGSetHTMLTemplate()
	}

	engine.HTMLRender = render.HTMLProduction{Template: templ.Funcs(engine.FuncMap)}
}

// SetFuncMap 设置用于template.FuncMap的FuncMap。
func (engine *Engine) SetFuncMap(funcMap template.FuncMap) {
	engine.FuncMap = funcMap
}

// NoRoute 为NoRoute添加处理程序。它默认返回404代码。
func (engine *Engine) NoRoute(handlers ...HandlerFunc) {
	engine.noRoute = handlers
	engine.rebuild404Handlers()
}

// NoMethod sets the handlers called when... TODO.
func (engine *Engine) NoMethod(handlers ...HandlerFunc) {
	engine.noMethod = handlers
	engine.rebuild405Handlers()
}

// Use attaches a global middleware to the router. ie. the middleware attached though Use() will be
// included in the handlers chain for every single request. Even 404, 405, static files...
// For example, this is the right place for a logger or error management middleware.
// 使用将全局中间件附加到路由器。即。通过Use（）连接的中间件将是
// 包含在每个请求的处理程序链中。甚至404,405，静态文件......
// 例如，这是记录器或错误管理中间件的正确位置。
func (engine *Engine) Use(middleware ...HandlerFunc) IRoutes {
	// 讲中间件传入到 group.Handlers , 实际上是一个slice
	engine.RouterGroup.Use(middleware...)
	engine.rebuild404Handlers()
	engine.rebuild405Handlers()
	return engine
}

func (engine *Engine) rebuild404Handlers() {
	engine.allNoRoute = engine.combineHandlers(engine.noRoute)
}

func (engine *Engine) rebuild405Handlers() {
	engine.allNoMethod = engine.combineHandlers(engine.noMethod)
}

func (engine *Engine) addRoute(method, path string, handlers HandlersChain) {
	assert1(path[0] == '/', "path must begin with '/'")
	assert1(method != "", "HTTP method can not be empty")
	assert1(len(handlers) > 0, "there must be at least one handler")

	debugPrintRoute(method, path, handlers)
	root := engine.trees.get(method)
	if root == nil {
		root = new(node)
		root.fullPath = "/"
		engine.trees = append(engine.trees, methodTree{method: method, root: root})
	}
	root.addRoute(path, handlers)
}

// Routes returns a slice of registered routes, including some useful information, such as:
// the http method, path and the handler name.
// 返回所有的路由信息，路由信息是一个树状结构
func (engine *Engine) Routes() (routes RoutesInfo) {
	for _, tree := range engine.trees {
		routes = iterate("", tree.method, routes, tree.root)
	}
	return routes
}

// 一个迭代方法
func iterate(path, method string, routes RoutesInfo, root *node) RoutesInfo {
	path += root.path
	if len(root.handlers) > 0 {
		handlerFunc := root.handlers.Last()
		routes = append(routes, RouteInfo{
			Method:      method,
			Path:        path,
			Handler:     nameOfFunction(handlerFunc),
			HandlerFunc: handlerFunc,
		})
	}
	for _, child := range root.children {
		routes = iterate(path, method, routes, child)
	}
	return routes
}

// Run 将路由器附加到http.Server并开始侦听和提供HTTP请求。
//这是http.ListenAndServe（addr，路由器）的快捷方式
//注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) Run(addr ...string) (err error) {
	defer func() { debugPrintError(err) }()

	// 解析地址
	address := resolveAddress(addr)
	debugPrint("Listening and serving HTTP on %s\n", address)
	// 监听地址
	err = http.ListenAndServe(address, engine)
	return
}

// RunTLS attaches the router to a http.Server and starts listening and serving HTTPS (secure) requests.
// It is a shortcut for http.ListenAndServeTLS(addr, certFile, keyFile, router)
// Note: this method will block the calling goroutine indefinitely unless an error happens.
func (engine *Engine) RunTLS(addr, certFile, keyFile string) (err error) {
	debugPrint("Listening and serving HTTPS on %s\n", addr)
	defer func() { debugPrintError(err) }()

	// 建立TLS协议
	err = http.ListenAndServeTLS(addr, certFile, keyFile, engine)
	return
}

// RunUnix attaches the router to a http.Server and starts listening and serving HTTP requests
// through the specified unix socket (ie. a file).
// Note: this method will block the calling goroutine indefinitely unless an error happens.
// 将路由器附加到http.Server并开始侦听和提供HTTP请求
// 通过指定的unix套接字（即文件）。
// 注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) RunUnix(file string) (err error) {
	debugPrint("Listening and serving HTTP on unix:/%s", file)
	defer func() { debugPrintError(err) }()

	os.Remove(file)
	// unix下的拿到套接字
	listener, err := net.Listen("unix", file)
	if err != nil {
		return
	}
	defer listener.Close()
	os.Chmod(file, 0777)
	err = http.Serve(listener, engine)
	return
}

// RunFd attaches the router to a http.Server and starts listening and serving HTTP requests
// through the specified file descriptor.
// Note: this method will block the calling goroutine indefinitely unless an error happens.
// 将路由器附加到ht
// tp.Server并开始侦听和提供HTTP请求
// 通过指定的文件描述符。
// 注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) RunFd(fd int) (err error) {
	debugPrint("Listening and serving HTTP on fd@%d", fd)
	defer func() { debugPrintError(err) }()

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd@%d", fd))
	listener, err := net.FileListener(f)
	if err != nil {
		return
	}
	defer listener.Close()
	err = http.Serve(listener, engine)
	return
}

// ServeHTTP conforms to the http.Handler interface.
// 符合http.Handler接口，实现golang中的鸭子模型
func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := engine.pool.Get().(*Context)
	// 重置一个响应写入者参数
	c.writermem.reset(w)
	// 设置context的request
	c.Request = req
	// 将其他的参数设置为初始状态
	c.reset()

	// 执行http请求
	engine.handleHTTPRequest(c)

	// 执行完http请求，不用销毁可以复用,将当前http请求放入请求池里面
	engine.pool.Put(c)
}

// HandleContext re-enter a context that has been rewritten.
// This can be done by setting c.Request.URL.Path to your new target.
// Disclaimer: You can loop yourself to death with this, use wisely.
// 重新输入已重写的上下文。
// 这可以通过将c.Request.URL.Path设置为新目标来完成。
// 免责声明：你可以用这个循环自己，明智地使用。
func (engine *Engine) HandleContext(c *Context) {
	// 因为处理http请求肯定会改变c.index的值，这个时候需要保存index的值，然后等执行http请求再赋值回去
	oldIndexValue := c.index
	// 重置上下文信息
	c.reset()
	engine.handleHTTPRequest(c)
	//赋值回去，这样重新执行这个请求的时候，处理方法可以按照以前的保存顺序执行
	c.index = oldIndexValue
}

// 操纵http请求
func (engine *Engine) handleHTTPRequest(c *Context) {
	httpMethod := c.Request.Method
	// 这里是一个uri
	rPath := c.Request.URL.Path
	unescape := false
	if engine.UseRawPath && len(c.Request.URL.RawPath) > 0 {
		rPath = c.Request.URL.RawPath
		// 解析路径值
		unescape = engine.UnescapePathValues
	}

	rPath = cleanPath(rPath)

	// 找到给定HTTP方法的树的根
	t := engine.trees
	for i, tl := 0, len(t); i < tl; i++ {
		// 先判断请求方法是不是一致的
		if t[i].method != httpMethod {
			continue
		}
		root := t[i].root
		// 在树中查找路线
		value := root.getValue(rPath, c.Params, unescape)
		// 如果查找到了，就对上下文对方法和参数，路径进行设置
		if value.handlers != nil {
			c.handlers = value.handlers
			// 如果解析路径值 params 会有参数
			c.Params = value.params
			c.fullPath = value.fullPath
			// 执行handlers
			c.Next()
			// 写入状态码
			c.writermem.WriteHeaderNow()
			return
		}
		// 如果http方式不是CONNECT 并且不是 "/"开头
		if httpMethod != "CONNECT" && rPath != "/" {
			// 如果如果开启了重定向斜杠路径,就重定向到后斜杠路径
			if value.tsr && engine.RedirectTrailingSlash {
				redirectTrailingSlash(c)
				return
			}
			// 如果如果开启了重定向修复路径，就重定向到修复到路径 , 如果成功了就结束执行
			if engine.RedirectFixedPath && redirectFixedPath(c, root, engine.RedirectFixedPath) {
				return
			}
		}
		break
	}

	// 如果开启了方法不允许访问
	if engine.HandleMethodNotAllowed {
		for _, tree := range engine.trees {
			// 如果方法就跳过，就代表，不执行下面405到错误
			if tree.method == httpMethod {
				continue
			}
			// 通过 rpath 和 unescape 找到路由解析树中node节点，设置不允许该方法到handler处理，并且设置状态吗和默认到请求体
			if value := tree.root.getValue(rPath, nil, unescape); value.handlers != nil {
				c.handlers = engine.allNoMethod
				serveError(c, http.StatusMethodNotAllowed, default405Body)
				return
			}
		}
	}
	c.handlers = engine.allNoRoute
	// 因为执行到这一步就是没有找到对应路径到方法，所以就抛出404错误
	serveError(c, http.StatusNotFound, default404Body)
}

var mimePlain = []string{MIMEPlain}

// 服务器错误
func serveError(c *Context, code int, defaultMessage []byte) {
	c.writermem.status = code
	// 切换到下一个 handler
	c.Next()
	if c.writermem.Written() {
		return
	}
	if c.writermem.Status() == code {
		// 设置content-type为文本类型
		c.writermem.Header()["Content-Type"] = mimePlain
		// 写入默认信息
		_, err := c.Writer.Write(defaultMessage)
		if err != nil {
			debugPrint("cannot write message to writer during serve error: %v", err)
		}
		return
	}
	c.writermem.WriteHeaderNow()
	return
}

// 重定向到有后斜杠到路径
func redirectTrailingSlash(c *Context) {
	req := c.Request
	p := req.URL.Path
	// 如果有转发前缀，需要加上前缀
	if prefix := path.Clean(c.Request.Header.Get("X-Forwarded-Prefix")); prefix != "." {
		p = prefix + "/" + req.URL.Path
	}
	code := http.StatusMovedPermanently // Permanent redirect, request with GET method
	if req.Method != "GET" {
		code = http.StatusTemporaryRedirect
	}
	//加上后斜杠
	req.URL.Path = p + "/"
	// 处理 "xxx//" 这样情况，这个时候要去掉一个/ "/"
	if length := len(p); length > 1 && p[length-1] == '/' {
		req.URL.Path = p[:length-1]
	}
	debugPrint("redirecting request %d: %s --> %s", code, p, req.URL.String())
	http.Redirect(c.Writer, req, req.URL.String(), code)
	c.writermem.WriteHeaderNow()
}

// 重定向到被修复到路径
func redirectFixedPath(c *Context, root *node, trailingSlash bool) bool {
	req := c.Request
	rPath := req.URL.Path

	if fixedPath, ok := root.findCaseInsensitivePath(cleanPath(rPath), trailingSlash); ok {
		// 设置状态码为永久重定向 	StatusMovedPermanently  = 301 // RFC 7231, 6.4.2
		code := http.StatusMovedPermanently // Permanent redirect, request with GET method
		// 但是如果不是GET请求修改为临时重定向 StatusTemporaryRedirect = 307 // RFC 7231, 6.4.7
		if req.Method != "GET" {
			code = http.StatusTemporaryRedirect
		}
		req.URL.Path = string(fixedPath)
		debugPrint("redirecting request %d: %s --> %s", code, rPath, req.URL.String())
		// http 重定向
		http.Redirect(c.Writer, req, req.URL.String(), code)
		// 将状态码写入请求头
		c.writermem.WriteHeaderNow()
		return true
	}
	return false
}
