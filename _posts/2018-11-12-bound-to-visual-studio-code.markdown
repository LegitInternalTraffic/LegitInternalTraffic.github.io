---
layout: post
title:  "Deloitte CTF: Bound to VSCode"
date:   2018-11-10 08:31:22 +0100
summary: "Test summary fjkhsd fkdsjf hdsjkfh"
author: "Davey Struijk"
tag: "Write-up"
categories: ctf
---
https://nodejs.org/en/blog/vulnerability/march-2018-security-releases/#node-js-inspector-dns-rebinding-vulnerability-cve-2018-7160

https://lock.cmpxchg8b.com/rebinder.html

## Intro

{Bound to VSCode}

{came across}
{we'll have to perform dns rebinding}

## The challenge

{first blabla vpn network, which has a client}

In the challenge description, we are told about a suspicious port 9333 being open, but not accessible from the outside. This is, in fact, an extension debugger process that's accidentally been started by VSCode. [This article](https://medium.com/0xcc/visual-studio-code-silently-fixed-a-remote-code-execution-vulnerability-8189e85b486b) describes the vulnerability we are going to exploit.

{will only scrape sites within the local network (our client). However, dns requests to the internet will succeed}

![image-title-here]({{ site.baseurl }}/images/vscode-1-scraper-page.png)

The source code looks {somewhat like this}:

{% highlight javascript %}
await page.goto(url).then(async function(response) {
    await page.waitFor(delay);
    // [...]
{% endhighlight %}

It's a script built on [puppeteer](https://github.com/GoogleChrome/puppeteer), which launches a headless instance of Google Chrome to scrape web pages. This means that, if we make it visit a page of our own, we can execute javascript within the context of that browser instance.

{% highlight bash %}
$ python -m http.server
{% endhighlight %}

## Problem: Same-origin policy

If it weren't for the browser's [same-origin policy](https://en.wikipedia.org/wiki/Same-origin_policy) checks, we would now be able to start talking with VSCode at `http://127.0.0.1:9333`. However, we can't do that unless our script is being served from the same origin (hostname *and* port).

This is where DNS rebinding comes in. Instead of passing `http://<attacker_ip>` as the url to scrape, we will provide a domain that randomly resolves to either `<attacker_ip>` or `127.0.0.1`, with a very short TTL. [Rbndr](https://github.com/taviso/rbndr) can generate such a domain for us.



...and then serve the file over http using python's [http.server](https://docs.python.org/3/library/http.server.html):

{% highlight bash %}
$ python -m http.server 9333
{% endhighlight %}


{Here's an overview of }



