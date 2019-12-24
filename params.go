package alipay

import (
	"fmt"
)

/*
	实现参数interface
*/

type Params struct {
	method    string            // 支付宝接口请求 方法
	notifyUrl string            //	回调地址
	p         map[string]string //	请求参数存放
}

/*
	@Descritpion 	初始化
	@Params
		method 	string
	@Return
		p 	Params
	@Author	cwy
*/
func NewParams(method string) *Params {
	return &Params{
		method: method,
		p:      make(map[string]string),
	}
}

/*
	@Description 	实现alipay  参数接口 获取method
	@Return
		method string
	@Author	cwy
*/
func (this *Params) GetMethod() string {
	return this.method
}

/*
	@Description 获取回调地址url
	@Return
		notify_url string
	Author cwy
*/
func (this *Params) GetNotifyUrl() string {
	return this.notifyUrl
}

/*
	@Description 	  实现获取请求参数
	@Return
		p 	map[string]string
	@Author	cwy
*/
func (this *Params) GetParams() map[string]string {
	return this.p
}

/*
	@Description 设置notify_url
	@Params
		notifyUrl string
	@Author	cwy
*/
func (this *Params) SetNotifyUrl(notifyUrl string) {
	this.notifyUrl = notifyUrl
}

/*
	@Descritpion 	填入参数
	@Params
		key 	string
		value 	interface{}
	@Author	cwy
*/
func (this *Params) Set(key string, value interface{}) {
	v, err := InterfaceToString(value)
	if err != nil {
		fmt.Println("format err ", err)
		return
	}
	this.p[key] = v
}
