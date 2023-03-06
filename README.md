# WPeChatGPT
- **A plugin for IDA** that can help to analyze binary file, it based on Gepetto which uses OpenAI's davinci-003 model.

- 当前 *WPeChatGPT* 支持的**功能**包括：
   - 分析函数的使用环境、预期目的、函数功能。
   - 重命名函数的变量。
   - 尝试用 python3 对函数进行还原，此功能主要是针对较小块的函数（如一个异或解密函数）。
   - 在当前函数中查找是否存在漏洞。
   - 尝试用 python 对漏洞函数生成对应的 EXP。
- *WPeChatGPT* 插件使用的是 OpenAI 基于GPT训练的 **text-davinci-003** 模型。  
  *v2.0* 版本后使用 OpenAI 最新的 **gpt-3.5-turbo** 模型。  

ChatGPT 的分析结果**仅供参考**，不然我们这些分析师就当场失业了。XD  

**PS**：我发现最近这几天 OpenAI-API 服务器的稳定性较差，如果遇到 `"HTTPSConnectionPool(host='api.openai.com', port=443)"` 相关的错误，可以稍等一会儿再尝试。
## 更新历史
|Version|Date|Comment|
|----|----|----|
|1.0|2023-02-28|Based on Gepetto.|
|1.1|2023-03-02|1. 删除分析加解密的功能。<br>2. 增加 python 还原函数的功能。<br>3. 修改了一些细节。|
|1.2|2023-03-03|1. 增加查找函数中二进制漏洞的功能。<br>2. 增加尝试自动生成对应 EXP 的功能。<br>3. 修改了一些细节。<br>（由于OpenAI服务器卡顿原因未测试上传）|
|2.0|2023-03-06|1. 完成测试 *v1.2* 版本漏洞相关功能。<br>2. 改用 OpenAI 最新发布的 **gpt-3.5-turbo** 模型|
## 安装
1. 运行如下命令安装所需包。
```
pip install -r ./requirements.txt
```
2. 修改脚本 `WPeChatGPT.py` 添加 API key 到变量 ***openai.api_key***。
3. 复制脚本文件 `WPeChatGPT.py` 到 IDA 的 plugins 文件夹, 最后重启 IDA 后即可使用。  

**`! NOTE`**：需要把 **IDA 的环境**设置为 **python3**，WPeChatGPT *2.0* 版本后需要使用**最新的 OpenAI Python 包**。
## 使用方法
支持在 IDA 中使用**右键、菜单栏或快捷键**任一。
- 快捷键：  
  `函数分析 = "Ctrl-Alt-G"`  
  `重命名函数变量 = "Ctrl-Alt-R"`  
  `二进制漏洞查找 = "Ctrl-Alt-E"`  

- 伪代码窗口右键：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInPseudocode.png" width="788"/>

- 菜单栏：Edit $\Rightarrow$ WPeChatGPT

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInEdit.png" width="360"/>
## 示例
使用方式：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/useExample.gif" width="790"/>

函数分析效果展示：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/resultExample.gif" width="790"/>

二进制漏洞查找效果展示：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/vulnExample.gif" width="790"/>
## 联系我
如果使用插件时遇到问题或有任何疑问，欢迎留言或发送邮件联系我。
## Acknowledgement
The project is based on *Gepetto* and inspired by it, you can visit https://github.com/JusticeRage/Gepetto to learn about the original method.
