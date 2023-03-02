# WPeChatGPT
- **A plugin for IDA** that can help to analyze binary file, it based on Gepetto which uses OpenAI's davinci-003 model.

- 当前 *WPeChatGPT* 支持的**功能**包括：
   - 分析函数的使用环境、预期目的、函数功能。
   - 重命名函数的变量。
   - 尝试用 python3 对函数进行还原，此功能主要是针对较小块的函数（如一个异或解密函数）。
- *WPeChatGPT* 插件使用的是 OpenAI 基于GPT训练的 **text-davinci-003** 模型。  
ChatGPT 的分析结果**仅供参考**，不然我们这些分析师就当场失业了。XD
## 更新历史
|Version|Date|Comment|
|----|----|----|
|1.0|2023-02-28|Based on Gepetto.|
|1.1|2023-03-02|1. 删除分析加解密的功能。<br>2. 增加 python 还原函数的功能。<br>3. 修改一些细节。|
## 安装
1. 运行如下命令安装所需包。
```
pip install -r ./requirements.txt
```
2. 修改脚本 `WPeChatGPT.py` 添加 API key 到变量 ***openai.api_key***。
3. 复制脚本文件 `WPeChatGPT.py` 到 IDA 的 plugins 文件夹, 最后重启 IDA 后即可使用。  

**`! NOTE`**：需要把 **IDA 的环境**设置为 **python3**。
## 使用方法
支持在 IDA 中使用**右键、菜单栏或快捷键**任一。
- 快捷键：  
  `函数分析 = "Ctrl-Alt-G"`  
  `重命名函数变量 = "Ctrl-Alt-R"`  
  `Python还原此函数 = "Ctrl-Alt-P"`  

- 伪代码窗口右键：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInPseudocode.png" width="788"/>

- 菜单栏：Edit $\Rightarrow$ WPeChatGPT

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInEdit.png" width="360"/>
## 示例
![image](https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/example.gif)
## 联系我
如果使用插件时遇到问题或有任何疑问，欢迎留言或发送邮件联系我。
## Acknowledgements
The project is based on *Gepetto* and inspired by it, you can visit https://github.com/JusticeRage/Gepetto to learn about the original method.
