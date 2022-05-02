#  sdn_tc_sdfs

#### 下載資料集  
https://www.unb.ca/cic/datasets/vpn.html  
  
## 分類器
  
#### 安裝python3 

https://www.python.org/downloads/  
PATH記得打勾  
PATH記得打勾  
PATH記得打勾  

#### 安裝python所需的模組  
<code>pip3 install sklearn joblib numpy pandas matplotlib seaborn pydotplus imblearn lightgbm pyarrow fastparquet</code>  
#### 預處理(輸入pcap, 輸出parquet)  
開啟classifier/preprocessing_pcap.py  
修改輸入輸出路徑  
大約需要8小時，放心如果記憶體不足中斷,手動重新開始後處理完成過的檔案不會重複處理  

#### 訓練model(輸入parquet, 輸出model)  
開啟classifier/train_test_sklearn.py  
修改輸入輸出路徑  
修改訓練類型  
大約需要15分鐘，可以在最底下寫每次要的參數選項自動執行多次  

#### 將model儲存到流量排程的資料夾(安裝控制器ryu的位置)
ryu/ryu/app/ryu_customapp/models/


## 流量排程

#### 安裝python3
<code>sudo apt-get update</code>  
<code>sudo apt-get install python3-pip</code>  
  
#### 讓2和3共存(非必要步驟)
安裝python2  
<code>sudo apt install python2</code>  
確認尚未設定過  
<code>sudo update-alternatives --list python</code>  
取得路徑  
<code>ls /usr/bin/python*</code>  
設定優先  
<code>sudo update-alternatives --install /usr/bin/python python /usr/bin/python2 1</code>  
<code>sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 2</code>  
確認完成設定  
<code>sudo update-alternatives --config python</code>  
<code>python --version</code>  

安裝pip2  
<code>wget https://bootstrap.pypa.io/pip/2.7/get-pip.py</code>  
<code>python2 get-pip.py</code>  
確認尚未設定過  
<code>sudo update-alternatives --list pip</code>  
取得路徑  
<code>pip --version</code>  
<code>pip3 --vesrion</code>  
設定優先  
<code>sudo update-alternatives --install /usr/bin/pip pip pip路徑 1</code>  
<code>sudo update-alternatives --install /usr/bin/pip pip pip3路徑 2</code>  
確認完成設定  
<code>sudo update-alternatives --config pip</code>  
<code>pip --version</code>  
  
#### 安裝所需的模組  
scapy

#### 安裝mininet
http://mininet.org/download/  
<code>git clone https://github.com/mininet/mininet</code>  
<code>sudo PYTHON=python3 mininet/util/install.sh -a</code>  

#### 安裝python所需的模組 (與分類器相同) 
<code>pip3 install sklearn joblib numpy pandas matplotlib seaborn pydotplus imblearn lightgbm pyarrow fastparquet</code>  

#### 安裝ryu  
https://ryu.readthedocs.io/en/latest/getting_started.html  
<code>git clone https://github.com/faucetsdn/ryu.git</code>  
<code>sudo apt install python3-ryu</code>  

####下載這個github的檔案放到對應資料夾
注意ryu/ryu/app/ryu_customapp/model中須放入model並修改ryu/ryu/app/simple_switch_13_nx.py中model的部份
注意pktreplay/pcap須放入pcap並修改exp_config/exp_config.py中


#### 設定重播pcap參數  
開啟exp_config/exp_config.py  
修改設定  
修改產生封包的開始時間：timestring  
修改pcap路徑：PKT_FILE_LIST  
修改select函數：SCHEDULER_TYPE  
選擇性設定  
修改pcap對應的傳送間隔：PKT_FILE_MAP  
修改其他設定如執行時間及頻寬相關參數  
  
#### 執行mininet  
<code>
sudo python3 mininet/custom/custom_example_nxtomini.py  
</code>  

#### 自動執行ryu  
<code>
ryu-manager ryu/ryu/app/simple_switch_13_nx.py  
</code>  
  
#### 等待
等待讀取pcap直到出現ready  
等待到設定的開始時間  
  
#### 執行中  
用於紀錄throughput，依照設定的時間每個間隔儲存，檔案在home目錄   

#### 執行完成  
用於計算latency，最後輸出client和server的收發時間，檔案在pktgen/timestamp目錄  
注意，時間過長可能會耗盡記憶體，需要修改儲存方式  
