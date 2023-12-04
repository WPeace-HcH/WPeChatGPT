import functools
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import re
import threading
import json
import sys, os

# Windows
path = os.path.dirname(os.path.abspath(__file__)) + "\\Auto-WPeGPT_WPeace\\"
# MacOS
#path = os.path.dirname(os.path.abspath(__file__)) + "/Auto-WPeGPT_WPeace/"
sys.path.append(path)
import Auto_WPeGPT

# Whether to use Chinese explanation code.
ZH_CN = True
# Set your API key here, or put in in the OPENAI_API_KEY environment variable.
openai.api_key = "ENTER_OPEN_API_KEY_HERE"
# Set your own proxy if necessary. (e.g. Clash)
#print("WPeChatGPT has appointed the proxy.")
#proxies = {'http': "http://127.0.0.1:7890", 'https': "http://127.0.0.1:7890"}
#openai.proxy = proxies
# Set reverse proxy URL if you need. (e.g. Azure)
#openai.api_base = "base_url"


# WPeChatGPT 分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 WPeChatGPT:Explain 分析，请查看注释或删除注释重新分析。@WPeace")
            else:
                print("The current function has been analyzed by WPeChatGPT:Explain, please check the comment or delete the comment to re-analyze. @WPeace")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("下面是一个C语言伪代码函数，分别分析该函数的预期目的、参数的作用、详细功能，最后取一个新的函数名字。（用简体中文回答我，并且回答开始前加上'---GPT_START---'字符串结束后加上'---GPT_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0),
                0)
        # English
        else:
            query_model_async("Analyze the following C language pseudo-code function, respectively speculate on the use environment, expected purpose, and detailed function of the function, and finally choose a new name for this function. (add '---GPT_START---' string before the beginning of the answer and add '---GPT_END---' string after the end)\n" + str(decompiler_output), functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0), 0)
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
            if ZH_CN:
                print("当前函数已经完成过 WPeChatGPT:Python 分析，请查看注释或删除注释重新分析。@WPeace")
            else:
                print("The current function has been analyzed by WPeChatGPT:Python, please check the comment or delete the comment to re-analyze. @WPeace")
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
            query_model_async("Analyze the following C language pseudocode and restore it with python3 code. (Add '---GPT_Python_START---' string before the beginning of the answer and add '---GPT_Python_END---' string after the end)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 尝试寻找函数漏洞
class FindVulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_VulnFinder_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 WPeChatGPT:VulnFinder 分析，请查看注释或删除注释重新分析。@WPeace")
            else:
                print("The current function has been analyzed by WPeChatGPT:VulnFinder, please check the comment or delete the comment to re-analyze. @WPeace")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("查找下面这个C语言伪代码函数的漏洞并提出可能的利用方法。（用简体中文回答我，并且回答开始前加上'---GPT_VulnFinder_START---'字符串结束后加上'---GPT_VulnFinder_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2),
                0)
        # English
        else:
            query_model_async("Find the following C function vulnerabilty and suggest a possible way to exploit it.(Use English to answer me, and answer before plus '---GPT_VulnFinder_START---' the end of the string plus '---GPT_VulnFinder_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# WPeChatGPT 尝试对漏洞函数生成EXP
class expCreateHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_VulnPython_START---" in funcComment:
            if ZH_CN:
                print("当前函数已经完成过 WPeChatGPT:ExpCreater 分析，请查看注释或删除注释重新分析。@WPeace")
            else:
                print("The current function has been analyzed by WPeChatGPT:ExpCreater, please check the comment or delete the comment to re-analyze. @WPeace")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        if ZH_CN:
            query_model_async("使用Python构造代码来利用下面函数中的漏洞。（用简体中文回答我，并且回答开始前加上'---GPT_VulnPython_START---'字符串结束后加上'---GPT_VulnPython_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3),
                0)
        # English
        else:
            query_model_async("Use Python to construct code to exploit the vulnerabilities in the following functions.(Answer before plus '---GPT_VulnPython_START---' the end of the string plus '---GPT_VulnPython_END---' string)\n"
                              + str(decompiler_output),
                              functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3),
                              0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def autoChatFunc(funcTree:str, strings:str, callback):
    messages = []
    input_funcTree = funcTree
    messages.append({"role": "user", "content": input_funcTree})
    input_strings = strings
    messages.append({"role": "user", "content": input_strings})
    if ZH_CN:
        messages.append({"role": "user", "content": "结合该程序的函数调用结构及其所包含的字符串，猜测其运行目的及功能。"})
        messages.append({"role": "user", "content": "请再仔细分析后告诉我该程序的运行目的及大概功能。"})
    else:
        messages.append({"role": "user", "content": "Combining the function call structure of the program and the strings it contains, guess its purpose and function."})
        messages.append({"role": "user", "content": "Please tell me the purpose and general function of the program after careful analysis."})
    t = threading.Thread(target=chat_api_worker, args=(messages, "gpt-3.5-turbo", callback))
    t.start()


def chat_api_worker(messages, model, callback):
    try:
        response = openai.ChatCompletion.create(messages=messages, model=model)
    except Exception as e:
        if "maximum context length" in str(e):
            print("此二进制文件的分析数据超过了 GPT-3.5-API 的最大长度！请期待后续版本 :)@WPeace")
            return 0
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@WPeace")
            return 0
        else:
            print(f"General exception encountered while running the query: {str(e)}")
            return 0
    callback(response)


def handle_response(autoGptfolder, response):
    message = response.choices[0].message
    if ZH_CN:
        print("GPT 分析完毕，已将结果输出到文件夹：" + autoGptfolder + " 当中！")
    else:
        print("The GPT analysis is complete and the result has been output to the folder: " + autoGptfolder)
    fp = open(autoGptfolder + "GPT-Result.txt", "w")
    fp.write(message.content)
    fp.close()
    print("Auto-WPeGPT finished! :)@WPeace\n")


# Auto-WPeGPT 自动化分析
class autoHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        Auto_WPeGPT.main()
        idb_path = idc.get_idb_path()
        idb_name = 'WPe_' + os.path.basename(idb_path)
        autoGptfolder = os.path.join(os.getcwd(), idb_name) + '\\'
        functreeFilepath = autoGptfolder + "funcTree.txt"
        mainFunctreeFilepath = autoGptfolder + "mainFuncTree.txt"
        stringsFilepath = autoGptfolder + "effectiveStrings.txt"
        file = open(functreeFilepath, "r")
        functreeData = file.read()
        file.close()
        file = open(mainFunctreeFilepath, "r")
        mainFunctreeData = file.read()
        file.close()
        file = open(stringsFilepath, "r")
        stringsData = file.read()
        file.close()
        funcNumber = idaapi.get_func_qty()
        print("There are %d functions in total in this binary file." %funcNumber)
        if funcNumber < 150:
            callback_autogpt = functools.partial(handle_response, autoGptfolder)
            autoChatFunc(functreeData, stringsData, callback_autogpt)
        else:
            callback_autogpt = functools.partial(handle_response, autoGptfolder)
            autoChatFunc(mainFunctreeData, stringsData, callback_autogpt)
        print("Auto-WPeGPT v0.2 start to analysis...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# Gepetto query_model Method
def query_model(query, cb, max_tokens=2500):
    """
    向 gpt-3.5-turbo 发送查询的函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": query}
            ]
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0]["message"]["content"]), ida_kernwin.MFF_WRITE)
    except openai.InvalidRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(f"gpt-3.5-turbo could not complete the request: {str(e)}")
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(f"WPeChatGPT-Warning: Context length too long! Try reducing tokens to {max_tokens}...")
            print("Request to gpt-3.5-turbo sent retried...")
            query_model(query, cb, max_tokens)
        else:
            print("Unfortunately, this function is too large to be analyzed using ChatGPT-gpt-3.5-turbo API. @WPeace")
    except openai.OpenAIError as e:
        if "That model is currently overloaded with other requests" in str(e) or "Request timed out" in str(e):
            print("ChatGPT-gpt-3.5-turbo API 繁忙，请稍后重试或检查代理。@WPeace")
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@WPeace")
        else:
            print(f"OpenAI server could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")


# Gepetto query_model_async Method
def query_model_async(query, cb, time):
    """
    创建线程调用 query_model 函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    :param time: whether it is a retry.
    """
    if time == 0:
        if ZH_CN:
            print("正在发送 ChatGPT-gpt-3.5-turbo API 请求，完成后将输出提示。@WPeace")
        else:
            print("Sending ChatGPT-gpt-3.5-turbo API request, will output a prompt when completed. @WPeace")
        print("Request to gpt-3.5-turbo sent...")
    else:
        if ZH_CN:
            print("正在重新发送 ChatGPT-gpt-3.5-turbo API 请求。@WPeace")
        else:
            print("Resending ChatGPT-gpt-3.5-turbo API request. @WPeace")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# Gepetto comment_callback Method
def comment_callback(address, view, response, cmtFlag, printFlag):
    """
    在对应地址处设置注释的回调函数。
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add the response as a comment in IDA.
    # 通过参数控制不同形式添加注释
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 1)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("gpt-3.5-turbo query finished!")
    if printFlag == 0:
        if ZH_CN:
            print("WPeChatGPT:Explain 完成分析，已对函数 %s 进行注释。@WPeace" %idc.get_func_name(address))
        else:
            print("WPeChatGPT:Explain finished analyzing, function %s has been commented. @WPeace" %idc.get_func_name(address))
    elif printFlag == 1:
        if ZH_CN:
            print("WPeChatGPT:Python 完成分析，已在函数末尾地址 %s 汇编处进行注释。@WPeace" %hex(address))
        else:
            print("WPeChatGPT:Python finished parsing, commented at assembly at address %s at end of function. @WPeace" %hex(address))
    elif printFlag == 2:
        if ZH_CN:
            print("WPeChatGPT:VulnFinder 完成分析，已对函数 %s 进行注释。@WPeace" %idc.get_func_name(address))
        else:
            print("WPeChatGPT: VulnFinder finished analyzing, function %s has been annotated. @WPeace" %idc.get_func_name(address))
    elif printFlag == 3:
        if ZH_CN:
            print("WPeChatGPT:ExpCreater 完成分析，已对函数 %s 进行注释。@WPeace" %idc.get_func_name(address))
        else:
            print("WPeChatGPT:ExpCreater finished analyzing, commented on function %s. @WPeace" %idc.get_func_name(address))


# Gepetto rename_callback Method
def rename_callback(address, view, response, retries=0):
    """
    重命名函数变量的回调函数。
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from gpt-3.5-turbo
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print("ChatGPT-gpt-3.5-turbo API has no valid response, please try again later. @WPeace")
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
            print("ChatGPT-gpt-3.5-turbo API has no valid response, please try again later. @WPeace")
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
    print("gpt-3.5-turbo query finished!")
    if ZH_CN:
        print(f"WPeChatGPT:RenameVariable 完成分析，已重命名{len(replaced)}个变量。@WPeace")
    else:
        print(f"WPeChatGPT:RenameVariable Completed analysis, renamed {len(replaced)} variables. @WPeace")


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


# Add context menu actions
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.explain_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.rename_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.python_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.vulnFinder_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.expPython_action_name, "WPeChatGPT/")


class myplugin_WPeChatGPT(idaapi.plugin_t):
    autoWPeGPT_action_name = "WPeChatGPT:Auto-WPeGPT"
    autoWPeGPT_menu_path = "Edit/WPeChatGPT/Auto-WPeGPT/Auto-WPeGPT v0.2"
    explain_action_name = "WPeChatGPT:Explain_Function"
    explain_menu_path = "Edit/WPeChatGPT/函数分析"
    rename_action_name = "WPeChatGPT:Rename_Function"
    rename_menu_path = "Edit/WPeChatGPT/重命名函数变量"
    python_action_name = "WPeChatGPT:Python_Function"
    python_menu_path = "Edit/WPeChatGPT/Python还原此函数"
    vulnFinder_action_name = "WPeChatGPT:VulnFinder_Function"
    vulnFinder_menu_path = "Edit/WPeChatGPT/二进制漏洞查找"
    expPython_action_name = "WPeChatGPT:VulnPython_Function"
    expPython_menu_path = "Edit/WPeChatGPT/尝试生成Exploit"
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
        if ZH_CN:
            # create Auto-WPeGPT action
            autoWPeGPT_action = idaapi.action_desc_t(self.autoWPeGPT_action_name,
                                                  '二进制文件自动化分析 v0.2',
                                                  autoHandler(),
                                                  "",
                                                  '使用 gpt-3.5-turbo 对二进制文件进行自动化分析',
                                                  199)
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            # Function explaining action
            explain_action = idaapi.action_desc_t(self.explain_action_name,
                                                  '函数分析',
                                                  ExplainHandler(),
                                                  "Ctrl+Alt+G",
                                                  '使用 gpt-3.5-turbo 分析当前函数',
                                                  199)
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            # Variable renaming action
            rename_action = idaapi.action_desc_t(self.rename_action_name,
                                                 '重命名函数变量',
                                                 RenameHandler(),
                                                 "Ctrl+Alt+R",
                                                 "使用 gpt-3.5-turbo 重命名当前函数的变量",
                                                 199)
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            # python function action
            python_action = idaapi.action_desc_t(self.python_action_name,
                                                 'Python还原此函数',
                                                 PythonHandler(),
                                                 "",
                                                 "使用 gpt-3.5-turbo 分析当前函数并用python3还原",
                                                 199)
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            # find vulnerabilty action
            vulnFinder_action = idaapi.action_desc_t(self.vulnFinder_action_name,
                                                  '二进制漏洞查找',
                                                  FindVulnHandler(),
                                                  "Ctrl+Alt+E",
                                                  '使用 gpt-3.5-turbo 在当前函数中查找漏洞',
                                                  199)
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            # create exploit action
            expPython_action = idaapi.action_desc_t(self.expPython_action_name,
                                                  '尝试生成Exploit',
                                                  expCreateHandler(),
                                                  "",
                                                  '使用 gpt-3.5-turbo 尝试对漏洞函数生成EXP',
                                                  199)
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            # Register context menu actions
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 is ready.")
            print("WPeChatGPT v2.4 works fine! :)@WPeace\n")
        else:
            # create Auto-WPeGPT action
            autoWPeGPT_action = idaapi.action_desc_t(self.autoWPeGPT_action_name,
                                                  'Automated analysis v0.2',
                                                  autoHandler(),
                                                  "",
                                                  '使用 gpt-3.5-turbo 对二进制文件进行自动化分析',
                                                  199)
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            # Function explaining action
            explain_action = idaapi.action_desc_t(self.explain_action_name,
                                                  'Function analysis',
                                                  ExplainHandler(),
                                                  "Ctrl+Alt+G",
                                                  '使用 gpt-3.5-turbo 分析当前函数',
                                                  199)
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            # Variable renaming action
            rename_action = idaapi.action_desc_t(self.rename_action_name,
                                                 'Rename function variables',
                                                 RenameHandler(),
                                                 "Ctrl+Alt+R",
                                                 "使用 gpt-3.5-turbo 重命名当前函数的变量",
                                                 199)
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            # python function action
            python_action = idaapi.action_desc_t(self.python_action_name,
                                                 'Python restores this function',
                                                 PythonHandler(),
                                                 "",
                                                 "使用 gpt-3.5-turbo 分析当前函数并用python3还原",
                                                 199)
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            # find vulnerabilty action
            vulnFinder_action = idaapi.action_desc_t(self.vulnFinder_action_name,
                                                  'Vulnerability finding',
                                                  FindVulnHandler(),
                                                  "Ctrl+Alt+E",
                                                  '使用 gpt-3.5-turbo 在当前函数中查找漏洞',
                                                  199)
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            # create exploit action
            expPython_action = idaapi.action_desc_t(self.expPython_action_name,
                                                  'Try to generate Exploit',
                                                  expCreateHandler(),
                                                  "",
                                                  '使用 gpt-3.5-turbo 尝试对漏洞函数生成EXP',
                                                  199)
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            # Register context menu actions
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 is ready.")
            print("WPeChatGPT v2.4 works fine! :)@WPeace\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name)
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        idaapi.detach_action_from_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name)
        idaapi.detach_action_from_menu(self.expPython_menu_path, self.expPython_action_name)
        if self.menu:
            self.menu.unhook()
        return


def PLUGIN_ENTRY():
    if openai.api_key == "ENTER_OPEN_API_KEY_HERE":
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("未找到 API_KEY，请在脚本中填写 openai.api_key! :(@WPeace")
            raise ValueError("No valid OpenAI API key found")
    return myplugin_WPeChatGPT()
