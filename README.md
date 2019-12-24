# alipay

支付宝接口sdk

# SDK 初始化
sdk初始化需要一个必须参数,为alipay对应上线应用的app_id.对应的其他参数为非必要参数.
证书可以通过sdk的load方法加载 也可以通过初始化时传入

# 初始化传入
```go
sdk, err := ailpay.New(appId,
        //  应用私钥证书路径      例如  test_alipay_interface/appPrivateKey.txt"
        alipay.SetAppPrivateCertFilePath(appPrivateKeyFilepath),
        //  应用公钥证书路径      例如  test_alipay_interface/appCertPublicKey_2018012202027971.crt
        alipay.SetAppPublicCertFilePath(appCertPublicKeyFilepath),
        //  支付宝公钥证书路径  例如  test_alipay_interface/alipayCertPublicKey_RSA2.crt
        alipay.SetAlipayPublicCertFilePath(alipayCertPublicKeyFilepath),
        // 支付宝根证书                 例如 test_alipay_interface/alipayRootCert.crt
        alipay.SetAlipayRootCertFilePath(alipayRootCertFilepath),
        // 是否开启debug   这个可以打印部分信息
		alipay.SetDev(true),
	)
```

# load 加载
```go
sdk , err := alipay.New(appId)
// 通过路径方式加载应用私钥  
sdk.LoadAppPrivateKeyFromFile(appPrivateKeyFilepath)
//  通过字符串的方式加载应用私钥
sdk.LoadAppPrivateKey(appPrivateString)


//  通过路径的方式加载 应用公钥
sdk.LoadAppPublicSnFromFile(appCertPublicKeyFilepath)
// 直接字符串加载
sdk.LoadAppPublicSn(appCertPublicString)

// 文件加载 alipay  公钥
sdk.LoadAlipayPublicSnFromFile(alipayCertPublicKeyFilepath)
//  字符串加载
sdk.LoadAlipayPublicSn(alipayCertPublicString)

// 加载根证书
sdk.LoadAlipayRootSnFromFile(alipayRootCertFilepath)
// 字符串加载
sdk.LoadAlipayRootSn(alipayRootCertString)
```
# 发送请求的参数初始化
发送请求需要参数数据填写在 params 这个结构里面
```go
//  初始化 传入需要请求的alipay  method
par := alipay.NewParams("alipay.fund.trans.toaccount.transfer")
//  设置参数
par.Set("out_biz_no","balabla")
//  设置notify_urlerr
par.SetNotifyUrl(notifyUrl)
```

# 发送请求 
```go
// 定义返回结构体 这个位置不能用interface{} 不然会接受不到对应的数据 最好根据官方的对应参数穿件结构体
var result AlipayFundTansToaccountTransferResult
//  请求只要alipay  返回的code 不是成功的code  都会返回错误信息 可以打印查看
err := sdk.Do(par,"POST",&result)
```