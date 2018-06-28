package main

import (
	"net/url"
	"encoding/base64"
	"fmt"
	"time"
	"strconv"
	"net/http"
	"strings"
	"io/ioutil"
	"encoding/json"
	"os"
	"net/http/cookiejar"
	"crypto/rsa"
	"math/big"
	"crypto/rand"
	//"golang.org/x/text/encoding"
)

type Loginweibo struct{
	username			string
	pwd					string
	preData				*PreloginData
	client				*http.Client
	cookie				[]*http.Cookie
}

type PreloginData struct{
	Retcode				int  		`json:"retcode"`
	Servertime			int64		`json:"servertime"`
	Pcid				string		`json:"pcid"`
	Nonce				string		`json:"nonce"`
	Pubkey				string		`json:"pubkey"`
	Rsakv				string		`json:"rsakv"`
	Is_openlock			int			`json:"is_openlock"`
	Lm					int			`json:"lm"`
	Smsurl				string		`json:"smsurl"`
	Showpin				int			`json:"showpin"`
	Exectime			int			`json:"exectime"`
}
const(
	PRELOGIN_URL ="http://login.sina.com.cn/sso/prelogin.php"
	LOGIN_URL="http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)"
	FETCH_URL="https://weibo.com/tianjingaosu?is_all=1"
)

func main()  {
	j, _ := cookiejar.New(nil)
	weibo :=&Loginweibo{username:"xxx",pwd:"xxxxx",client:&http.Client{Jar:j}}
	err :=weibo.preLogin()
	if err !=nil{
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("prelogin Succeed")
	err = weibo.Login()
	if err !=nil{
		fmt.Println(err)
		os.Exit(1)
	}
	weibo.fetch()

}
//登陆
func (this *Loginweibo) Login() error{
	data :=url.Values{}
	data.Add("entry","weibo")
	data.Add("gateway","1")
	data.Add("from","")
	data.Add("savestate","7")
	data.Add("useticket","1")
	data.Add("pagerefer","")
	data.Add("service","miniblog")
	data.Add("vsnf","1")
	data.Add("su",this.get_suser())
	data.Add("sp",this.get_pwd())
	data.Add("servertime",strconv.FormatInt(this.preData.Servertime,10))
	data.Add("nonce",this.preData.Nonce)
	data.Add("pwencode","rsa2")
	data.Add("rsakv",this.preData.Rsakv)
	data.Add("encoding","UTF-8")
	data.Add("url","http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack")
	data.Add("returntype","META")
	data.Add("prelt","1")

	req, err := http.NewRequest("POST", LOGIN_URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_,err= this.request(req)
	if err !=nil{
		return err
	}
	purl,_:=url.Parse(LOGIN_URL)
	fmt.Println("login ok")
	cookies :=this.client.Jar.Cookies(purl)
	this.cookie = cookies
	return nil
}
// 预登录
func (this *Loginweibo)preLogin() error {
	data := url.Values{}
	data.Add("entry","weibo")
	data.Add("callback","sinaSSOController.preloginCallBack")
	data.Add("su",this.get_suser())
	data.Add("rsakt","mod")
	data.Add("checkpin","1")
	data.Add("client","ssologin.js(v1.4.18)")
	data.Add("_",this.get_mtime())

	req,_:=http.NewRequest("POST",PRELOGIN_URL,strings.NewReader(data.Encode()))
	req.Header.Set("Accept","*/*")
	req.Header.Set("Accept-Language","zh-CN,zh;q=0.8")
	req.Header.Set("Connection","keep-alive")
	req.Header.Set("Referer","http://weibo.com/?c=spr_web_sq_kings_weibo_t001")
	req.Header.Set("Host","login.sina.com.cn")
	req.Header.Set("User-Agent","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.154 Safari/537.36 LBBROWSER")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	result,err := this.request(req)
	if err !=nil{
		return err
	}
	if strings.Index(result,"\"retcode\":0")==-1 && strings.Index(result,"sinaSSOController.preloginCallBack")==-1{
		return fmt.Errorf("result error")
	}
	result=strings.Replace(result,"sinaSSOController.preloginCallBack(","",1)
	result=strings.Replace(result,")","",1)
	//fmt.Println(result)
	retData := &PreloginData{}
	err = json.Unmarshal([]byte(result),retData)
	if err !=nil{
		fmt.Println(err)
		return fmt.Errorf("result json parse  error")
	}
	this.preData = retData
	return nil
}
// 通用方法
func (this *Loginweibo) request(req *http.Request)(string,error){
	resp,err := this.client.Do(req)
	if err !=nil{
		fmt.Println(err)
		return "",fmt.Errorf("http error")
	}
	defer resp.Body.Close()
	buf ,err := ioutil.ReadAll(resp.Body)
	if err !=nil{
		fmt.Println(err)
		return "",fmt.Errorf("read body error")
	}
	result := string(buf)
	return result,nil
}
//用户名
func (this *Loginweibo)get_suser() string{
	username_ := url.QueryEscape(this.username)
	return base64.URLEncoding.EncodeToString([]byte(username_))
}
//时间戳
func (this *Loginweibo) get_mtime() string{
	//time.Now().UnixNano()*1000000
	return strconv.FormatInt(time.Now().UnixNano()/1000000,10)
}
//密码加密
func (this *Loginweibo) get_pwd() string{
	//fmt.Println(this.preData.Pubkey)
	i :=new(big.Int)
	rsaPublickey,ok:= i.SetString(this.preData.Pubkey,16)
	if !ok{
		return ""
	}
	key:=rsa.PublicKey{N:rsaPublickey,E:65537}
	message :=  strconv.FormatInt(this.preData.Servertime,10) + "\t" + this.preData.Nonce + "\n" + this.pwd
	//fmt.Println(rsaPublickey)
	result,err := rsa.EncryptPKCS1v15(rand.Reader,&key,[]byte(message))
	if err !=nil{
		fmt.Println(err)
		return ""
	}
	return fmt.Sprintf("%X", result)
}

// 改造这个方法 可以返回内容 直接传给go-query使用
// 提取网页内容
func (this *Loginweibo) fetch(){
	req, _ := http.NewRequest("GET", FETCH_URL,nil)
	purl,_:= url.Parse(FETCH_URL)
	this.client.Jar.SetCookies(purl,this.cookie)
	result,err :=this.request(req)
	if err !=nil{
		fmt.Println(err)
		return
	}
	fmt.Println(result)
}
