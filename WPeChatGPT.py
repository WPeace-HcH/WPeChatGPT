import functools
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import os
import re
import textwrap
import threading
import json

# 是否使用中文代码解释
ZH_CN = True
# Set your API key here, or put in in the OPENAI_API_KEY environment variable.
openai.api_key = "ENTER_OPEN_API_KEY_HERE"


# WPeChatGPT 分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_START---" in funcComment:
            print("当前函数已经完成过 WPeChatGPT:Explain 分析，请查看注释或删除注释重新分析。@WPeace")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("对下面的C语言伪代码函数进行分析，分别推测该函数的使用环境、预期目的、详细的函数功能，最后为这个函数取一个新的名字。（用简体中文回答我，并且回答开始前加上'---GPT_START---'字符串结束后加上'---GPT_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0), 
                0)
        # English
        else:
            query_model_async("Can you explain what the following C function does and suggest a better name for it?(Use English to answer me, and answer before plus '---GPT_START---' the end of the string plus '---GPT_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0), 
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 重命名变量函数
class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Analyze the following C function:\n" + str(decompiler_output) +
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names"
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.",
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v), 
                          0)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 使用python3对函数进行还原
class PythonHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # lastAddr 为函数的最后一行汇编代码地址
        lastAddr = idc.prev_head(idc.get_func_attr(idaapi.get_screen_ea(), idc.FUNCATTR_END))
        # 获取对应注释
        addrComment = getAddrComment(lastAddr)
        if "---GPT_Python_START---" in str(addrComment):
            print("当前函数已经完成过 WPeChatGPT:Python 分析，请查看注释或删除注释重新分析。@WPeace")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("分析下面的C语言伪代码并用python3代码进行还原。（回答开始前加上'---GPT_Python_START---'字符串结束后加上'---GPT_Python_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1), 
                0)
        # English
        else:
            query_model_async("Parse the following C pseudocode and restore with python3 code.(Use English to answer me, and answer before plus '---GPT_Python_START---' the end of the string plus '---GPT_Python_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1), 
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# Gepetto comment_callback Method
def comment_callback(address, view, response, cmtFlag, printFlag):
    """
    在对应地址处设置注释的回调函数。
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, width=80, replace_whitespace=False))
    # Add the response as a comment in IDA.
    # 通过参数控制不同形式添加注释
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("davinci-003 query finished!")
    if printFlag == 0:
        print("WPeChatGPT:Explain 完成分析，已对函数 %s 进行注释。@WPeace" %idc.get_func_name(address))
    elif printFlag == 1:
        print("WPeChatGPT:Python 完成分析，已在函数汇编地址 %s 处进行注释。@WPeace" %hex(address))


# Gepetto rename_callback Method
def rename_callback(address, view, response, retries=0):
    """
    重命名函数变量的回调函数。
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from davinci-003
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print("ChatGPT-davinci-003 API 暂无有效响应, 请稍后重试。@WPeace")
            return
        print(f"Cannot extract valid JSON from the response. Asking the model to fix it...")
        query_model_async("The JSON document provided in this response is invalid. Can you fix it?\n" + response,
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print("ChatGPT-davinci-003 API 暂无有效响应, 请稍后重试。@WPeace")
            return
        print(f"The JSON document returned is invalid. Asking the model to fix it...")
        query_model_async("Please fix the following JSON document:\n" + j.group(0),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)
    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print("davinci-003 query finished!")
    print(f"WPeChatGPT:RenameVariable 完成分析，已重命名{len(replaced)}个变量。@WPeace")


# Gepetto query_model Method
def query_model(query, cb, max_tokens=2500):
    """
    向 davinci-003 发送查询的函数。
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.Completion.create(
            model = "text-davinci-003",
            prompt = query,
            temperature = 0.6,
            max_tokens = max_tokens,
            top_p = 1,
            frequency_penalty = 1,
            presence_penalty = 1,
            timeout = 60    # Wait 60 seconds maximum
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].text), ida_kernwin.MFF_WRITE)
    except openai.InvalidRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(f"davinci-003 could not complete the request: {str(e)}")
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(f"WPeChatGPT-Warning：上下文长度过长! 尝试将 tokens 减少为 {max_tokens}...")
            print("Request to davinci-003 sent retried...")
            query_model(query, cb, max_tokens)
        else:
            print("可惜可惜，这个函数太大了不能使用 ChatGPT-davinci-003 API 来分析。@WPeace")
    except openai.OpenAIError as e:
        if "That model is currently overloaded with other requests" in str(e) or "You can retry your request" in str(e):
            print("ChatGPT-davinci-003 API 繁忙，请稍后重试。@WPeace")
        else:
            print(f"davinci-003 could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")


# Gepetto query_model_async Method
def query_model_async(query, cb, time):
    """
    创建线程调用 query_model 函数。
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    :param time: whether it is a retry.
    """
    if time == 0:
        print("正在发送 ChatGPT-davinci-003 API 请求，完成后将输出提示。@WPeace")
        print("Request to davinci-003 sent...")
    else:
        print("正在重新发送 ChatGPT-davinci-003 API 请求。@WPeace")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# Add context menu actions
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.explain_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.rename_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.python_action_name, "WPeChatGPT/")


# 获取函数注释
def getFuncComment(address):
    cmt = idc.get_func_cmt(address, 0)
    if not cmt:
        cmt = idc.get_func_cmt(address, 1)
    return cmt


# 获取地址注释
def getAddrComment(address):
    cmt = idc.get_cmt(address, 0)
    if not cmt:
        cmt = idc.get_cmt(address, 1)
    return cmt


class myplugin_WPeChatGPT(idaapi.plugin_t):
    explain_action_name = "WPeChatGPT:Explain_Function"
    explain_menu_path = "Edit/WPeChatGPT/函数分析"
    rename_action_name = "WPeChatGPT:Rename_Function"
    rename_menu_path = "Edit/WPeChatGPT/重命名函数变量"
    python_action_name = "WPeChatGPT:Python_Function"
    python_menu_path = "Edit/WPeChatGPT/Python还原此函数"
    wanted_name = 'WPeChatGPT'
    wanted_hotkey = ''
    comment = "WPeChatGPT Plugin for IDA"
    help = "Find more information at https://github.com/wpeace-hch"
    menu = None
    flags = 0
    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              '函数分析',
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              '使用 davinci-003 分析当前函数',
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             '重命名函数变量',
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             "使用 davinci-003 重命名当前函数的变量",
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
        # Encryption and decryption algorithm explaining action
        python_action = idaapi.action_desc_t(self.python_action_name,
                                             'Python还原此函数',
                                             PythonHandler(),
                                             "Ctrl+Alt+P",
                                             "使用 davinci-003 分析当前函数并用python3还原",
                                             199)
        idaapi.register_action(python_action)
        idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()
        print("WPeChatGPT v1.1 based on Gepetto works fine! :)@WPeace\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        if self.menu:
            self.menu.unhook()
        return


def PLUGIN_ENTRY():
    if not openai.api_key:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("未找到 API_KEY，请在脚本中填写 openai.api_key! :(@WPeace")
            raise ValueError("No valid OpenAI API key found")
    return myplugin_WPeChatGPT()
