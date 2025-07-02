# SSRF
Introduce the SSRF vulnerabilities in LLM-As-Chatbot project.

LLM-As-Chatbot, an open source project that provides LLM-powered chatbot services (via Gradio UI and Discord bot) using various open-source instruction-following models with 3.3k stars on GitHub, has a SSRF vulnerability in the file [dumb_utils.py](https://github.com/deep-diver/LLM-As-Chatbot/blob/99c2c03efececba39a633589775f77989f93deff/dumb_utils.py#L154). Since the project extracts and accesses the URL links from the question entered by users without any inspection, it may be exploited by attackers to access intranet IP addresses and protocols.


## Version
Favorites-web Project latest

## Attack Vector
In the LLM-As-Chatbot project, the discord_app.py uses `urlextract`, a Python third-party library for extracting URL links from text to extract urls from user input. Then the project uses the user-supplied URL as an argument to the Python `urllib` library function `urlopen()` through a series of function calls. Since the input is not properly sanitized or restricted, an attacker can construct a malicious URL to trigger a server-side request forgery (SSRF). This can cause the attacker to make arbitrary server-side HTTP requests to internal services or external systems.

## Vulnerability causes
`build_prompt_and_reply` is an important function that receives and processes user input in discord_app.py.

```python
async def build_prompt_and_reply(executor, user_name, user_id):
    other_job_on_progress = False
    loop = asyncio.get_running_loop()
    
    print(queue.qsize())
    msg = await queue.get()
    user_msg, user_args = parse_req(
        msg.content.replace(f"@{user_name} ", "").replace(f"<@{user_id}> ", ""), global_vars.gen_config
    )
    
    if user_msg == "help":
        await msg.channel.send(helps.get_help())
    elif user_msg == "model-info":
        await msg.channel.send(helps.get_model_info(model_name, model_info))
    elif user_msg == "default-params":
        await msg.channel.send(helps.get_default_params(global_vars.gen_config, user_args["max-windows"]))
    else:
        try:
            ppm = await build_ppm(msg, user_msg, user_name, user_id)

            if user_args["internet"] and serper_api_key is not None:
                other_job_on_progress = True
                progress_msg = await msg.reply("Progress 🚧", mention_author=False)

                internet_search_ppm = copy.deepcopy(ppm)
                internet_search_prompt = f"My question is '{user_msg}'. Based on the conversation history, give me an appropriate query to answer my question for google search. You should not say more than query. You should not say any words except the query."
                internet_search_ppm.pingpongs[-1].ping = internet_search_prompt
                internet_search_prompt = await build_prompt(
                    internet_search_ppm, 
                    ctx_include=False,
                    win_size=user_args["max-windows"]
                )
                if tgi_server_addr is None:
                    internet_search_prompt_response = await loop.run_in_executor(
                        executor, gen_method, internet_search_prompt, user_args
                    )
                else:
                    internet_search_prompt_response = await gen_method(internet_search_prompt, user_args)
                internet_search_prompt_response = post.clean(internet_search_prompt_response)

                ppm.pingpongs[-1].ping = internet_search_prompt_response

                await progress_msg.edit(
                    content=f"• Search query re-organized by LLM: {internet_search_prompt_response}", 
                    suppress=True
                )

                searcher = SimilaritySearcher.from_pretrained(device=global_vars.device)

                logs = ""
                for step_ppm, step_msg in InternetSearchStrategy(
                    searcher, serper_api_key=serper_api_key
                )(ppm, search_query=internet_search_prompt_response, top_k=8):
                    ppm = step_ppm
                    logs = logs + step_msg + "\n"
                    await progress_msg.edit(content=logs, suppress=True)
            else:
                url_extractor = URLExtract()
                urls = url_extractor.find_urls(user_msg)
                print(f"urls = {urls}")

                if len(urls) > 0:
                    progress_msg = await msg.reply("Progress 🚧", mention_author=False)

                    other_job_on_progress = True
                    searcher = SimilaritySearcher.from_pretrained(device=global_vars.device)

                    logs = ""
                    for step_result, step_ppm, step_msg in URLSearchStrategy(searcher)(ppm, urls, top_k=8):
                        if step_result is True:
                            ppm = step_ppm
                            logs = logs + step_msg + "\n"
                            await progress_msg.edit(content=logs, suppress=True)
                        else:
                            ppm = step_ppm
                            logs = logs + step_msg + "\n"
                            await progress_msg.edit(content=logs, suppress=True)
                            await asyncio.sleep(2)
                            break

            prompt = await build_prompt(ppm, win_size=user_args["max-windows"])
            if tgi_server_addr is None:
                response = await loop.run_in_executor(executor, gen_method, prompt, user_args)
                response = post.clean(response)
            else:
                response = await gen_method(prompt, user_args)

            response = f"**{model_name}** 💬\n{response.strip()}"
            if len(response) >= max_response_length:
                response = response[:max_response_length]

            if other_job_on_progress is True:
                await progress_msg.delete()

            await msg.reply(response, mention_author=False)
        except IndexError:
            await msg.channel.send("Index error")
        except HTTPException:
            pass
```

This function uses the library method `URLExtract().find_urls()` to extract urls in user input and then passes the user-supplied urls to `URLSearchStrategy.__call__` method without properly restrict. 

```python
class URLSearchStrategy(CtxStrategy):
        
    def __call__(self, ppmanager: PPManager, urls, top_k=8, max_tokens=1024, keep_original=False):
        ppm = copy.deepcopy(ppmanager)
        last_ping = ppm.pingpongs[-1].ping
        # 1st yield
        ppm.add_pong("![loading](https://i.ibb.co/RPSPL5F/loading.gif)\n")
        ppm.append_pong("• Creating Chroma DB Collection...")
        yield True, ppm, "• Creating Chroma DB Collection √"
        
        chroma_client = chromadb.Client()
        try:
            chroma_client.delete_collection(self.db_name)
        except:
            pass
        
        col = chroma_client.create_collection(self.db_name)
        
        # 2nd yield
        ppm.replace_last_pong("![loading](https://i.ibb.co/RPSPL5F/loading.gif)\n")
        ppm.append_pong("• Creating Chroma DB Collection √\n")
        ppm.append_pong("• URL Searching...\n")
        yield True, ppm, "• URL Searching √"

        # HTML parsing
        search_results = []
        success_urls = []
        for url in urls:
            parse_result, contents = self._parse_html(url)
            if parse_result == True:
                success_urls.append(url)
                search_results.append(contents)
                
                ppm.append_pong(f"    - {url} √\n")
                yield True, ppm, f" ▷ {url} √"

        ...
```

`URLSearchStrategy.__call__` method in dumb_utils.py directly passes the urls to `URLSearchStrategy._parse_html` through a for loop without any inspection, too. `URLSearchStrategy._parse_html` method try to passed user-supplied url to `urllib.urlopen`, which directly leads to access to any ip address provided by user.

```python
def _parse_html(self, url):
        try: 
            page = urlopen(url, timeout=5)
            html_bytes = page.read()
            html = html_bytes.decode("utf-8")
        except:
            return False, None
        
        text = ""
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.findAll('p'):
            for string in tag.strings:
                text = text + string
                
        for tag in soup.findAll('pre'):
            for string in tag.strings:
                text = text + string

        text = self._replace_multiple_newlines(text)
        return True, text
```

## Vulnerability reproduce

1. Obtain the required tokens according to the project's readme and create application, server and bot on Discord.


2. Install the required Python packages on host1(9.134.210.173), download the required model files, and run the project.
![normal access](https://github.com/DYX217/directory-traversal/blob/main/image/normal.png)

3. Test whether the chatbot status is online in Discord, which indicates whether the previous operation is successful.


4. Create a simple html page on host2(9.134.209.238) and use tcpdump to capture traffic from host1.


5. Ask the chatbot a question on Discord, which include a URL pointing to host2.


6. From the console output of host1, the answer in discord and the packet capture record on host2, it can be seen that the chatbot accessed the link specified in the question.


## Impact

Users can access any intranet IP addresses and protocols.
