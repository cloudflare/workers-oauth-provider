## Written using Claude

This library (including the schema documentation) was largely written with the help of [Claude](https://claude.ai), the AI model by Anthropic. Claude's output was thoroughly reviewed by Cloudflare engineers with careful attention paid to security and compliance with standards. Many improvements were made on the initial output, mostly again by prompting Claude (and reviewing the results). Check out the commit history to see how Claude was prompted and what code it produced.

**"NOOOOOOOO!!!! You can't just use an LLM to write an auth library!"**

"haha gpus go brrr"

In all seriousness, two months ago (January 2025), I ([@kentonv](https://github.com/kentonv)) would have agreed. I was an AI skeptic. I thought LLMs were glorified Markov chain generators that didn't actually understand code and couldn't produce anything novel. I started this project on a lark, fully expecting the AI to produce terrible code for me to laugh at. And then, uh... the code actually looked pretty good. Not perfect, but I just told the AI to fix things, and it did. I was shocked.

To emphasize, **this is not "vibe coded"**. Every line was thoroughly reviewed and cross-referenced with relevant RFCs, by security experts with previous experience with those RFCs. I was _trying_ to validate my skepticism. I ended up proving myself wrong.

Again, please check out the commit history -- especially early commits -- to understand how this went.
