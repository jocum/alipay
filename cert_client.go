package alipay

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
	文档地址 https://docs.open.alipay.com/291/106118
	支付宝证书处理
	公钥证书方式下，开发者发送给开放平台网关请求参数中，
	需携带应用公钥证书SN（app_cert_sn）、支付宝根证书SN（alipay_root_cert_sn），
	若不携带这两个参数，网关会拒绝请求。
	SN值是通过解析X.509证书文件中签发机构名称（name）以及内置序列号（serialNumber），
	将二者拼接后的字符串计算MD5值获取，可参考开放平台SDK源码中AlipaySignature.getCertSN实现app_cert_sn的提取：
*/
const (
	//	密钥
	CERTIFICATE_END   = "-----END CERTIFICATE-----"       //	证书后缀
	PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----"      //	公钥前缀
	PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----"        //	公钥后缀
	PKCS1_PREFIX      = "-----BEGIN RSA PRIVATE KEY-----" //	pkcs1 私钥前缀
	PKCS1_SUFFIX      = "-----END RSA PRIVATE KEY-----"   //	pkcs1 私钥后缀
	PKCS8_PREFIX      = "-----BEGIN PRIVATE KEY-----"     //	pkcs8 	私钥前缀
	PKCS8_SUFFIX      = "-----END PRIVATE KEY-----"       //	pkcs8 	私钥后缀
	CONTENT_TYPE      = "application/x-www-form-urlencoded;charset=utf-8"

	//初始化默认参数
	_defaultFormat        = "JSON"                                     //数据格式
	_defaultCharset       = "utf-8"                                    //	数据编码字符集
	_defaultVersion       = "1.0"                                      //	接口版本
	_defaultSignType      = "RSA2"                                     //加密方法
	_apiSandboxURL        = "https://openapi.alipaydev.com/gateway.do" //	沙箱环境
	_apiProductURL        = "https://openapi.alipay.com/gateway.do"    // 正式环境
	_apiProductionMAPIURL = "https://mapi.alipay.com/gateway.do"       //	异步回调验证正式环境

	//	支付宝返回结果
	_alipayResponseSuffix        = "_response"
	_alipayErrResponse           = "error_response"
	ALIPAY_RESPONSE_SUCCESS_CODE = "10000"
)

var (
	ErrCertificateFailed        error = errors.New("certificate failed to load")
	ErrPublicKeyNotInRSAFormat  error = errors.New("public key not in RSA format")
	ErrPrivateKeyNotInRSAFormat error = errors.New("private key not in RSA format")
	ErrParamsNotNull            error = errors.New("params is not null")
	ErrResponseNotFormat        error = errors.New("alipay response not format")
)

/*
	证书存储结构体
*/
type CertClient struct {
	mu       sync.Mutex
	Client   *http.Client //	http 请求客户端
	appId    string       //	应用在支付宝后台生成时的id
	format   string       // 返回的数据格式  例如 json  xml
	charset  string       //	字符集
	signType string       //	加密方式
	version  string       //	版本信息

	appPublicCertSn          string                    // 应用公钥证书序列号
	appPublicCertFilepath    string                    //	应用公钥证书路径
	appPrivateKey            *rsa.PrivateKey           //	应用私钥
	appPrivateCertFilepath   string                    //	应用私钥证书路径
	alipayPublicCertSn       string                    //支付宝公钥证书序列号
	alipayPublicCertFilepath string                    //	支付宝公钥证书路径
	alipayPublicKeys         map[string]*rsa.PublicKey // 支付宝公钥证书内容
	alipayRootCertSn         string                    // 支付宝根证书序列号
	alipayRootCertFilepath   string                    //	支付宝根证书路径

	dev             bool   //	是否测试环境
	apiURL          string //	请求接口url
	notifyVerifyURL string //	异步结果通知 验证接口url
}

/*
	@Description 	初始化支付宝请求
	@Params
		appId 	string 	支付宝appId
		opts 		[]Option
	@Return
		c 	*CertClient
	@Author	cwy
*/
func New(appId string, opts ...Option) (*CertClient, error) {
	//初始化 client  设置默认参数
	client := &CertClient{
		Client:           http.DefaultClient,
		appId:            appId,
		format:           _defaultFormat,
		charset:          _defaultCharset,
		signType:         _defaultSignType,
		version:          _defaultVersion,
		apiURL:           _apiProductURL,
		notifyVerifyURL:  _apiProductionMAPIURL,
		alipayPublicKeys: make(map[string]*rsa.PublicKey),
	}
	// 设置参数
	for _, o := range opts {
		o.apply(client)
	}
	// 判断环境  沙箱环境好像有问题 请求不通 暂时不启用
	// if client.dev {
	// 	client.apiURL = _apiSandboxURL
	// 	client.notifyVerifyURL = _apiSandboxURL
	// }
	// 加载应用公钥信息
	if client.appPublicCertFilepath != "" {
		if err := client.LoadAppPublicSnFromFile(client.appPublicCertFilepath); err != nil {
			return nil, err
		}
	}
	// 加载应用私钥信息
	if client.appPrivateCertFilepath != "" {
		if err := client.LoadAppPrivateKeyFromFile(client.appPrivateCertFilepath); err != nil {
			return nil, err
		}
	}
	//  加载支付宝公钥信息
	if client.alipayPublicCertFilepath != "" {
		if err := client.LoadAlipayPublicSnFromFile(client.alipayPublicCertFilepath); err != nil {
			return nil, err
		}
	}
	// 加载支付宝根证书信息
	if client.alipayRootCertFilepath != "" {
		if err := client.LoadAlipayRootSnFromFile(client.alipayRootCertFilepath); err != nil {
			return nil, err
		}
	}
	return client, nil
}

/*
	@Descritpion 	获取应用私钥
	@Params
		certKey 	string
	@Return
		error
	@Author	cwy
*/
func (this *CertClient) LoadAppPrivateKey(certKey string) (err error) {
	// 解析 私钥
	var privateKey *rsa.PrivateKey
	privateKey, err = this.ParsePKSC1PrivateKey(certKey)
	if err != nil {
		privateKey, err = this.ParsePKSC8PrivateKey(certKey)
		if err != nil {
			return
		}
	}
	this.mu.Lock()
	this.appPrivateKey = privateKey
	this.mu.Unlock()
	return
}

/*
	@Desdcription 	通过文件的方式加载私钥
	@Params
		filepath	string
	@Return
		error
	@Author	cwy
*/
func (this *CertClient) LoadAppPrivateKeyFromFile(filepath string) error {
	byteConten, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	return this.LoadAppPrivateKey(string(byteConten))
}

/*
	@Descritpion 	从证书中提取序列号
	@Params
		certKey 	string   证书密钥
	@Return
		err	error
	@Author	cwy
*/
func (this *CertClient) LoadAppPublicSn(certKey string) error {
	//	解析证书
	certificate, err := this.ParseCertificate([]byte(certKey))
	if err != nil {
		return err
	}
	sn := getCertSN(certificate)
	this.mu.Lock()
	this.appPublicCertSn = sn
	this.mu.Unlock()
	return nil
}

/*
	@Descritpion 	加载应用公钥证书数据 根据支付宝要求生成 序列号
	@Params
		filePath	string
	@Return
		err		error
	@Author	cwy
*/
func (this *CertClient) LoadAppPublicSnFromFile(filePath string) error {
	//	读取文件内容
	byteContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return this.LoadAppPublicSn(string(byteContent))
}

/*
	@Descritpion 加载支付宝公钥序列以及公钥
	@Params
		cert 	string 	证书字符串
	@Return
		err		error
	@Author	cwy
*/
func (this *CertClient) LoadAlipayPublicSn(certKey string) error {
	//	 解析签名 数据中解析单个证书。
	certificate, err := this.ParseCertificate([]byte(certKey))
	if err != nil {
		return err
	}
	//	从解析的证书中获取支付宝公钥
	alipayPublicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrPublicKeyNotInRSAFormat
	}
	sn := getCertSN(certificate)
	this.mu.Lock()
	this.alipayPublicKeys[sn] = alipayPublicKey
	this.alipayPublicCertSn = sn
	this.mu.Unlock()
	return nil
}

/*
	@Descritpion 加载支付宝公钥序列以及公钥 通过证书路径
	@Params
		filepath  	string
	@Return
		err	error
	@Author	cwy
*/
func (this *CertClient) LoadAlipayPublicSnFromFile(filepath string) error {
	byteConten, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	return this.LoadAlipayPublicSn(string(byteConten))
}

/*
	@Description 	获取支付宝根证书密钥 提取序列
		支付宝根证书 是一个证书链 独立获取每个密钥的sn 用 "_" 拼接
	@Params
		certs 	string	根证书 证书链字符串
	@Return
		err 	error
	@Author	cwy
*/
func (this *CertClient) LoadAlipayRootSn(certs string) error {
	//	根据 数字签名结束字符串 拆分证书链
	certList := strings.Split(certs, CERTIFICATE_END)
	//	初始化 sn 列表 容量不超过数字证书数量
	snList := make([]string, 0, len(certList))
	//	循环解析每个证书
	for _, cert := range certList {
		//	拼接回 拆分丢失的证书链
		cert = cert + CERTIFICATE_END
		// 解析证书 获取证书对象
		certificate, _ := this.ParseCertificate([]byte(cert))
		//	判断证书不为空  并且  加密方式 为   x509.SHA256WithRSA  或者  x509.SHA1WithRSA
		if certificate != nil && (certificate.SignatureAlgorithm == x509.SHA256WithRSA || certificate.SignatureAlgorithm == x509.SHA1WithRSA) {
			snList = append(snList, getCertSN(certificate))
		}
	}
	this.mu.Lock()
	this.alipayRootCertSn = strings.Join(snList, "_")
	this.mu.Unlock()
	return nil
}

/*
	@Descritpion 	加载支付宝根证书 通过路径
	@Params
		filepath string 	文件路径
	@Return
		error
	@Authro	cwy
*/
func (this *CertClient) LoadAlipayRootSnFromFile(filepath string) error {
	byteContent, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	return this.LoadAlipayRootSn(string(byteContent))
}

/*
	@Descritpion  解析证书
	@Params
		b 	[]byte	证书字节切片
	@Return
		certificate  *x509.Certificate
		err		error
	@Author	cwy
*/
func (this *CertClient) ParseCertificate(b []byte) (*x509.Certificate, error) {
	//	解码 pem 格式证书/私钥
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, ErrCertificateFailed
	}
	//	从给定的 ASN.1 DER 数据中解析单个证书。
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

/*
	@Description 	请求参数处理成 url.Values
	@Parasms
		param 	AlipayParam
	@Return
		error
	@Author	cwy
*/
func (this *CertClient) ParamsToURLValues(param AlipayParam) (url.Values, error) {
	var values = url.Values{}
	//	基础公用参数 写入
	values.Add("app_id", this.appId)                                                 //	应用appid
	values.Add("method", param.GetMethod())                                          //	请求的接口方法
	values.Add("format", this.format)                                                //	返回数据格式  例:json
	values.Add("charset", this.charset)                                              //	编码格式 	例:UTF-8
	values.Add("sign_type", this.signType)                                           //	加密方式 例:RSA2
	values.Add("timestamp", time.Now().In(time.Local).Format("2006-01-02 15:04:05")) //	时间
	values.Add("version", this.version)                                              //	接口版本信息
	values.Add("app_cert_sn", this.appPublicCertSn)                                  //	app 公用序列号
	values.Add("alipay_root_cert_sn", this.alipayRootCertSn)                         //	支付宝根证书 序列号
	if param.GetNotifyUrl() != "" {
		values.Add("notify_url", param.GetNotifyUrl())
	}
	//	请求参转化 json 生成biz_content
	bizContentByte, err := json.Marshal(param.GetParams())
	if err != nil {
		return nil, err
	}
	//	写入biz_content
	values.Add("biz_content", string(bizContentByte))
	// 加密生成 sign
	sign, err := this.Sign(values, crypto.SHA256)
	if err != nil {
		fmt.Println("sign err", err)
		return nil, err
	}
	values.Add("sign", sign)
	if this.dev {
		fmt.Printf("需要传递的参数 url.Values 结构 %+v \n", values)
	}

	return values, nil
}

/*
	@Description 	对参数去空格  排序  加密 得到密文
	@Params
		values 	url.Values 	url 参数
		privateKey 	*rsa.PrivateKey 	app应用私钥
		has 	crypto.Hash 	加密方式
	@Return
		sign 	string 	加密后的密文 再经过base64 处理
		err		error
	@Author	cwy
*/
func (this *CertClient) Sign(values url.Values, hash crypto.Hash) (string, error) {
	src := paramsToAlipayString(values)
	if this.dev {
		fmt.Println("需要生成签名的源字符串 ", src)
	}
	//	加密
	signByte, err := RSASign([]byte(src), this.appPrivateKey, hash)
	if err != nil {
		return "", err
	}
	sign := base64.StdEncoding.EncodeToString(signByte)
	return sign, nil
}

/*
	@Description 	参数验签
	@Params
		params 	url.Values 	需要验签的数据
	@Return
		ok 	bool
		err	error
	@Author	cwy
*/
func (this *CertClient) VerifySign(params url.Values) (bool, error) {
	// 获取公钥
	alipayPublicSn := params.Get("alipay_cert_sn")
	if alipayPublicSn == "" {
		alipayPublicSn = this.alipayPublicCertSn
	}
	alipayPublicKey, err := this.getAlipayPublicKey(alipayPublicSn)
	if err != nil {
		return false, err
	}
	// 获取sign
	sign := params.Get("sign")
	// 从params 中删除sign
	delete(params, "sign")
	// 去除sign type
	delete(params, "sign_type")
	//	根据支付宝 要求拼接成签名字符串
	src := paramsToAlipayString(params)
	if this.dev {
		fmt.Println("支付宝异步验签字符串 ", src)
	}
	return verifySign([]byte(src), sign, alipayPublicKey)
}

/*
	@Description  数据验签
	@Params
		dataByte 	[]byte		需要验签的数据  按支付宝格式要求的字符串转成的 []byte
		sign 	string			需要校验的签名
		publicKey 	*rsa.PublicKey 	 验签需要的公钥 即支付宝公钥
	@Return
		ok 	bool
		err	error
	@Author	cwy
*/
func verifySign(dataByte []byte, sign string, publicKey *rsa.PublicKey) (bool, error) {
	//	支付宝的sign 是经过base64 处理的 先解密
	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}
	//	进行验签
	if err := RSAVerifySign(dataByte, signByte, publicKey, crypto.SHA256); err != nil {
		return false, err
	}
	return true, nil
}

/*
	@Descripion 	格式化PKSC1 私钥
	@Params
		privateKey 	string
	@Return
		pksc1 []byte
	@Author	cwy
*/
func (this *CertClient) FormatPKSC1PrivateKey(privateKey string) []byte {
	privateKey = strings.Replace(privateKey, PKCS8_PREFIX, "", 1)
	privateKey = strings.Replace(privateKey, PKCS8_SUFFIX, "", 1)
	return FormatKey(privateKey, PKCS1_PREFIX, PKCS1_SUFFIX, 64)
}

/*
	@Descritpion 	格式化PKSC8 私钥
	@Params
		privateKey 	string
	@Return
		pksc1 []byte
	@Author	cwy
*/
func (this *CertClient) FormatPKSC8PrivateKey(privateKey string) []byte {
	privateKey = strings.Replace(privateKey, PKCS1_PREFIX, "", 1)
	privateKey = strings.Replace(privateKey, PKCS1_SUFFIX, "", 1)
	return FormatKey(privateKey, PKCS8_PREFIX, PKCS8_SUFFIX, 64)
}

/*
	@Description  获取格式化PKSC1 私钥
	@Params
		key 	string
	@Return
		privateKey 	*rsa.PrivateKey
		err		error
	@Author	cwy
*/
func (this *CertClient) ParsePKSC1PrivateKey(key string) (*rsa.PrivateKey, error) {
	certByte := this.FormatPKSC1PrivateKey(key)
	block, _ := pem.Decode(certByte)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, err
}

/*
	@Description  获取格式化PKSC8 私钥
	@Params
		key 	string
	@Return
		privateKey 	*rsa.PrivateKey
		err		error
	@Author	cwy
*/
func (this *CertClient) ParsePKSC8PrivateKey(key string) (*rsa.PrivateKey, error) {
	certByte := this.FormatPKSC8PrivateKey(key)
	block, _ := pem.Decode(certByte)
	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := privateKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrPrivateKeyNotInRSAFormat
	}
	return privateKey, nil
}

/*
	@Description 	请求支付宝接口 回去返回结果
	@Params
		params 	AlipayParam
		requestMethod 	string 	请求接口方式  例如  GET  , POST
		result 	interface{} 	返回的结果数据
	@Return
		err 	error
	@Author	cwy
*/
func (this *CertClient) Do(params AlipayParam, requestMethod string, result interface{}) error {
	if params == nil {
		return ErrParamsNotNull
	}
	// 转化成url.Values 数据 并补全基础数据  签名加密sign
	values, err := this.ParamsToURLValues(params)
	if err != nil {
		return err
	}

	//	转化成 io.Reader 实现
	buff := strings.NewReader(values.Encode())
	// http 请求对象
	req, err := http.NewRequest(requestMethod, this.apiURL, buff)
	if err != nil {
		return err
	}
	//	设置 header 头
	req.Header.Set("Content-Type", CONTENT_TYPE)
	// 发送请求
	resp, err := this.Client.Do(req)
	// 优先关闭资源
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return err
	}
	// 读取返回数据
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	data := string(body)
	//	dev 模式打印部分信息
	if this.dev {
		fmt.Println("支付宝反馈数据原字符串", data)
	}
	// 将数据解析入  res
	var res map[string]interface{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}
	var alipayErr AlipayErr
	//	解析是否为返回错误信息
	errResponse, ok := res[_alipayErrResponse]
	//	如果错误 返回错误信息
	if ok {
		if err := Conversion(errResponse, &alipayErr); err != nil {
			return err
		}
		if this.dev {
			fmt.Printf("支付宝标准错误结构体 %+v \n ", alipayErr)
		}
		return &alipayErr
	}
	//	获取返回数据 key
	responseKey := strings.Replace(params.GetMethod(), ".", "_", -1) + _alipayResponseSuffix
	contentResponse, ok := res[responseKey]
	if !ok {
		return ErrResponseNotFormat
	}
	//	判断sign 是否存在
	var sign string
	if signInterface, ok := res["sign"]; ok {
		if signString, ok := signInterface.(string); ok {
			sign = signString
		}
	}
	//	如果sign为空 先当做错误处理
	if sign == "" {
		if err := Conversion(contentResponse, &alipayErr); err != nil {
			return err
		}
		//	公钥接口请求成功时不会返回sign 这里做判断过滤
		if alipayErr.Code != ALIPAY_RESPONSE_SUCCESS_CODE {
			return &alipayErr
		}
	}
	//	sign 存在 做 sign 校验
	//  获取alipay  返回的 公钥 sn
	var alipayPublicCertSn string
	if alipayPublicCertSnInterface, ok := res["alipay_cert_sn"]; ok {
		if alipayPublicCertSnString, ok := alipayPublicCertSnInterface.(string); ok {
			alipayPublicCertSn = alipayPublicCertSnString
		}
	}
	// 获取alipay 公钥
	alipayPublicKey, err := this.getAlipayPublicKey(alipayPublicCertSn)
	src := regBodyFromResponseKey(data, responseKey)
	if this.dev {
		fmt.Println("支付宝同步返回验签字符串", src)
	}
	//	验签
	if ok, err := verifySign([]byte(src), sign, alipayPublicKey); !ok {
		return err
	}
	//	验签成功返回数据
	return json.Unmarshal([]byte(src), result)
}

/*
	@Description 获取支付宝公钥  某些情况下需要去支付宝重新下载公钥 (具体什么情况我还没找到)
	@Params
		alipayPublicSn	string
	@Return
		key 	*rsa.PublicKey
		err		error
	@Author	cwy
*/
func (this *CertClient) getAlipayPublicKey(alipayPublicSn string) (key *rsa.PublicKey, err error) {
	// 开启 读写锁
	this.mu.Lock()
	defer this.mu.Unlock()
	if alipayPublicSn == "" {
		alipayPublicSn = this.alipayPublicCertSn
	}
	//	获取存储的alipay 公钥
	key = this.alipayPublicKeys[alipayPublicSn]
	if key != nil {
		return
	}
	//	不存在公钥从支付下载新的公钥
	downloadRes, err := this.AlipayPublicKeyDownlaod(alipayPublicSn)
	if err != nil {
		return
	}
	// base64 解码
	certByte, err := base64.StdEncoding.DecodeString(downloadRes.Response.AliPayCertContent)
	if err != nil {
		return
	}
	//  x509 解码
	certificate, err := this.ParseCertificate(certByte)
	if err != nil {
		return
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return
	}
	this.alipayPublicCertSn = getCertSN(certificate)
	this.alipayPublicKeys[this.alipayPublicCertSn] = key
	return
}

type CertDownloadRsp struct {
	Response struct {
		Code              string `json:"code"`
		Msg               string `json:"msg"`
		SubCode           string `json:"sub_code"`
		SubMsg            string `json:"sub_msg"`
		AliPayCertContent string `json:"alipay_cert_content"`
	} `json:"alipay_open_app_alipaycert_download_response"`
}

/*
	@Description 从支付宝获取新的公钥
	@Params
		alipayPublicSn 	string
	@Return
		certRsp 	*CertDownloadRsp
		err		error
	@Author	cwy
*/
func (this *CertClient) AlipayPublicKeyDownlaod(alipayPublicSn string) (result *CertDownloadRsp, err error) {
	// 初始化请求
	params := NewParams("alipay.open.app.alipaycert.download")
	params.Set("alipay_cert_sn", alipayPublicSn)
	err = this.Do(params, "POST", result)
	return
}

/*
	@Description 根据支付宝规则提取序列
		SN值是通过解析X.509证书文件中签发机构名称（name）以及内置序列号（serialNumber），
		将二者拼接后的字符串计算MD5值获取
	@Params
		certificate 	*x509.certificate
	@Return
		sn 	string
	@Author	cwy
*/
func getCertSN(certificate *x509.Certificate) string {
	var value = md5.Sum([]byte(certificate.Issuer.String() + certificate.SerialNumber.String()))
	return hex.EncodeToString(value[:])
}

/*
	@Descripton 	url.Values 参数 根据支付宝要求 去空格 排序 拼接成对应字符串
	@Params
		p 	url.Values
	@Return
		src 	string 		拼接而成的字符串
	@Author	cwy
*/
func paramsToAlipayString(p url.Values) string {
	if p == nil {
		return ""
	}
	vStringList := make([]string, 0)
	//	循环参数去除空格 将值不为空的数据  用= 拼接
	for key := range p {
		//	sign 不参与签名
		if key == "sign" {
			continue
		}
		v := strings.TrimSpace(p.Get(key))
		if len(v) > 0 {
			vStringList = append(vStringList, key+"="+v)
		}
	}
	//	对参数排序
	sort.Strings(vStringList)
	// 将所有参数 用& 拼接
	src := strings.Join(vStringList, "&")
	return src
}

/*
	@Description 获取需要验签的数据字符串  坑爹的支付宝 我只能用正则匹配去拿
	@Params
		body 	string 	返回的字符串
		responseKey 	string 	json 字符串数据的中 真正数据的 key 部分
	@Return
		src 	string 	匹配到的字符串
	@Author	cwy
*/
func regBodyFromResponseKey(body string, responseKey string) string {
	reg, err := regexp.Compile(responseKey + "\":(\\{.*\\})(,|\\})")
	if err != nil {
		return ""
	}
	ss := reg.FindStringSubmatch(body)
	if len(ss) > 2 {
		return ss[1]
	}
	return ""
}
