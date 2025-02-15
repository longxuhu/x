---
comments: true
---

# Gitlab[^1] 使用 Cravatar[^2]

## 修改`gitlab.rb`文件

```rb linenums="1" hl_lines="3 4"
### Gravatar Settings

gitlab_rails['gravatar_plain_url'] = 'https://cravatar.cn/avatar/%{hash}?s=%{size}&d=identicon'
gitlab_rails['gravatar_ssl_url'] = 'https://cravatar.cn/avatar/%{hash}?s=%{size}&d=identicon'
```

[^1]: [Using the Libravatar service with GitLab](https://docs.gitlab.com/ee/administration/libravatar.html)
[^2]: [Cravatar 官方 API 文档](https://cravatar.com/developer/api)