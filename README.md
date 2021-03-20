# 概要
DHCP DISCOVER 及び DHCP REQUEST を送信してきた機器に対して、
それぞれ、 DHCP OFFER 及び DHCP ACK を送信するプログラム。

DHCPの仕組み、C言語による通信プログラムの学習用に作成しているため、
現状IPアドレス・サブネットマスク・デフォルトゲートウェイ等の設定値はプログラムに直接埋め込みとなっている。
後々、機器に付与するアドレス範囲の指定など、設定値のカスタマイズ昨日も追加したい。

# 使用方法
`$ make`コマンドで実行ファイル(dhcp_server)を生成する。
`$ sudo ./dhcp_server`コマンドでプログラムを実行する。
DHCPの各要求に対する応答を行う回数を入力すると、受信したDHCPパケットに対しての応答を開始する。