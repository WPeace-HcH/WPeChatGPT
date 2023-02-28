# WPeChatGPT
- **A plugin for IDA** that can help to analyze binary file, it based on Gepetto which uses OpenAI's(ChatGPT) davinci-003 model.

- 当前 *WPeChatGPT* 支持的**功能**包括：
   - 分析函数的使用环境、预期目的、函数功能。
   - 重命名函数的变量。
   - 分析函数是否包含加解密算法，并尝试用 python3 还原。
## 更新历史
|Version|Date|Comment|
|----|----|----|
|1.0|2023-02-28|Based on Gepetto|
## 安装
1. 运行如下命令安装所需包。
```
pip install -r ./requirements.txt
```
2. 修改脚本 `WPeChatGPT.py` 添加 API key 到变量 ***openai.api_key***。
3. 复制脚本文件 `WPeChatGPT.py` 到 IDA 的 plugins 文件夹, 最后重启 IDA 后即可使用。
## 使用方法
支持在 IDA 中使用**右键、菜单栏或快捷键**任一。
- 快捷键：  
  `函数分析 = "Ctrl-Alt-G"`  
  `重命名函数变量 = "Ctrl-Alt-R"`  
  `加解密算法分析 = "Ctrl-Alt-E"`  

- 伪代码窗口右键：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInPseudocode.png" width="788"/>

- 菜单栏：Edit $\Rightarrow$ WPeChatGPT

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/menuInEdit.png" width="360"/>
## 示例
![image](https://github.com/WPeace-HcH/WPeChatGPT/blob/main/IMG/example.gif)
## 联系我
如果使用插件时遇到问题或有任何疑问，欢迎留言或发送邮件联系我。
## Acknowledgements
The project is based on Gepetto and inspired by it, you can visit https://github.com/JusticeRage/Gepetto to learn about the original method.
