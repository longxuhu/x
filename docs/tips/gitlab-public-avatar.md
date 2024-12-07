---
comments: true
tags:
  - Gitlab
---

# Gitlab换成国内公共头像服务

## 修改`gitlab.rb`文件

```rb linenums="1" hl_lines="3 4"
### Gravatar Settings

gitlab_rails['gravatar_plain_url'] = 'https://cravatar.cn/avatar/%{hash}?s=%{size}&d=identicon'
gitlab_rails['gravatar_ssl_url'] = 'https://cravatar.cn/avatar/%{hash}?s=%{size}&d=identicon'
```