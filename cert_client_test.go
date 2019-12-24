package alipay

import (
	"fmt"
	"testing"
	"time"
)

var (
	appId                       = "2018012202027971"
	appCertPublicKeyFilepath    = "./test_alipay_interface/appCertPublicKey_2018012202027971.crt"
	appPrivateKeyFilepath       = "./test_alipay_interface/appPrivateKey.txt"
	alipayRootCertFilepath      = "./test_alipay_interface/alipayRootCert.crt"
	alipayCertPublicKeyFilepath = "./test_alipay_interface/alipayCertPublicKey_RSA2.crt"
)

/*
	测试加载私钥信息
*/
func TestLoadAppPrivateKeyFromFile(t *testing.T) {
	var privateFilepath = "./app_private.txt"
	c, _ := New("123")
	err := c.LoadAppPrivateKeyFromFile(privateFilepath)
	fmt.Println("err ", err)
	fmt.Printf("certClietn %+v \n", c)
}

/*
	测试获取应用公钥信息
*/
func TestLoadAppPublicSnFromFile(t *testing.T) {
	var appPublicFilepath = "./appCertPublicKey_2021000197671847.crt"
	c, _ := New("345")
	err := c.LoadAppPublicSnFromFile(appPublicFilepath)
	fmt.Println("err ", err)
	fmt.Printf("certClietn %+v \n", c)
}

/*
	测试alipay 公钥证书加载
*/
func TestLoadAlipayPublicSnFromFile(t *testing.T) {
	var alipayPublicFilePath = "./alipayCertPublicKey_RSA2.crt"
	c, _ := New("456")
	err := c.LoadAlipayPublicSnFromFile(alipayPublicFilePath)
	fmt.Println("err ", err)
	fmt.Printf("certClietn %+v \n", c)
}

/*
	测试alipay  根证书加载
*/
func TestLoadAlipayRootSnFromFile(t *testing.T) {
	var alipayRootFilePath = "./alipayRootCert.crt"
	c, _ := New("567")
	err := c.LoadAlipayRootSnFromFile(alipayRootFilePath)
	fmt.Println("err ", err)
	fmt.Printf("certClietn %+v \n", c)
}

/*
	测试 单笔转账到支付宝账户接口
*/
type AlipayFundTansToaccountTransferResult struct {
	// Code     string `json:"code"`
	// Msg      string `json:"msg"`
	// SubCode  string `json:"sub_code"`
	// SubMsg   string `json:"sub_msg"`
	AlipayErr
	OrderId  string `json:"order_id"`
	OutBizNo string `json:"out_biz_no"`
	PayDate  string `json:"pay_date"`
}

func TestAlipayFundTansToaccountTransfer(t *testing.T) {
	client, err := New(appId,
		SetAppPrivateCertFilePath(appPrivateKeyFilepath),
		SetAppPublicCertFilePath(appCertPublicKeyFilepath),
		SetAlipayPublicCertFilePath(alipayCertPublicKeyFilepath),
		SetAlipayRootCertFilePath(alipayRootCertFilepath),
		// SetDev(true),
	)
	if err != nil {
		t.Error("new cient err", err)
	}
	t.Logf("client %+v \n", client)
	outBizNo := time.Now().Format("20060102150405")
	params := NewParams("alipay.fund.trans.toaccount.transfer")
	params.Set("out_biz_no", outBizNo)
	params.Set("payee_type", "ALIPAY_LOGONID")
	params.Set("payee_account", "13850354951")
	params.Set("amount", "0.01")
	params.Set("remark", "测试转账")
	var res AlipayFundTansToaccountTransferResult
	err = client.Do(params, "POST", &res)
	if err != nil {
		fmt.Println("err", err)
	}
	fmt.Printf("result %+v \n ", res)
}

// 测试正则
func TestRegBodyFromResponseKey(t *testing.T) {
	var resKey = "alipay_fund_trans_toaccount_transfer_response"
	var body = `{"alipay_fund_trans_toaccount_transfer_response":{"code":"10000","msg":"Success","order_id":"20191218110070001506060056811632","out_biz_no":"20191218103719","pay_date":"2019-12-18 10:37:20"`
	s := regBodyFromResponseKey(body, resKey)
	fmt.Println("s ", s)
}
