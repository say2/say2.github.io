---
layout: post
title: "블로그를 관리해보자"
author: "say2"
tags: ["blog", "jekyll","editor"]
categories: [Etc]
---

지금까지 신년계획은 늘 이뤄지지 않았지만! 올해도 반전은 없었다..ㅎ 매달 쓰려했던 블로그는 차일피일 미뤄져 거미줄이 생기고 말았다ㅎ

이게 다~ github 연동 jekyll블로그가 괜찮은 에디터가 없기때문이다..!라는 핑계를 대다가..

근데 잠깐, 세상아 멈춰! 이게 없을리가 있나..? 한번 찾아보기로 했다!

찾고자하는 에디터의 조건은 아래와 같다.


1. 이미지 복붙이 편해야 함! (요즘세상에 어찌 이미지를 폴더에 옮기고 링크를 입력해야되나..)

2. 온라인으로 어디서든 작업가능해야함!

3. 계정은  oauth로 해결해야함! (요즘세상에 누굴 믿는가!)

jekyll editor를 모아둔 [awesome-jekyll-editors](https://github.com/planetjekyll/awesome-jekyll-editors) 를 참고해서 하나씩 써보기로 했다. 


###  (1) 첫번째 후보 jekyll-admin
![jekyll-admin](/assets/img/post/image-20211219041350024.png)

세팅도 제일 쉽다. Gemfile에 
```
gem 'jekyll-admin', group: :jekyll_plugins
```
이거 한줄만 넣어주면 끝.

ui도 간단하고 editor기능도 잘 되어있다! 심플한 점 하나만큼은 100점이었다. 

그런데 online으로 작업하기에 애매하고, 이미지를 올리려면, static files 메뉴에서 업로드 폴더를 찾아가 이미지를 업로드한다음, post editor에서 직접 링킹 해줘야했다. 양보할수 없는 불편함이었다!

탈락..

### (2) 두번째 후보 netlify-cms
![netlify-cms](/assets/img/post/image-20211219050757503.png)

[awesome-jekyll-editors](https://github.com/planetjekyll/awesome-jekyll-editors) 에서 스타가 제일 많은 에디터였고, 정리된 블로그가 제대로 없어서 [메뉴얼](https://www.netlifycms.org/docs/add-to-your-site/) 을 보면서 로컬에 구축해보았다. 

jekyll기준으로 세팅하는 방법을 간략하게 정리해보자면,

1. 내 jekyll디렉토리에 /admin 디렉토리를 판다. 

2. admin/index.html을 만든다. 

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Content Manager</title>
</head>
<body>
  <!-- Include the script that builds the page and powers Netlify CMS -->
  <script src="https://unpkg.com/netlify-cms@^2.0.0/dist/netlify-cms.js"></script>
</body>
</html>
```

3. admin/config.yml을 작성한다.
내 블로그 기준(oauth+github) 아래와 같이 작성을 하였다. 

```plaintext
backend:
  name: github
  repo: say2/say2.github.io
  branch: master # Branch to update (optional; defaults to master)
  baseurl: http://localhost:3000

media_folder: "assets/img/post"

collections:
  - name: "blog" # Used in routes, e.g., /admin/collections/blog
    label: "Blog" # Used in the UI
    folder: "_posts" # The path to the folder where the documents are stored
    create: true # Allow users to create new documents in this collection
    slug: "{{year}}-{{month}}-{{day}}-{{slug}}" # Filename template, e.g., YYYY-MM-DD-title.md
    fields: # The fields for each document, usually in front matter
      - {label: "Layout", name: "layout", widget: "hidden", default: "blog"}
      - {label: "Title", name: "title", widget: "string"}
      - {label: "Author", name: "author", widget: "string"}
      - {label: "Publish Date", name: "date", widget: "datetime"}
      - {label: "Featured Image", name: "thumbnail", widget: "image"}
      - {label: "Body", name: "body", widget: "markdown"}
```

oauth 서버는 [https://github.com/settings/applications/new](https://github.com/settings/applications/new) 에서 OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET를 얻은다음 [여기](https://www.netlifycms.org/docs/external-oauth-clients/) 에서 아무거나 세팅하면 된다. 나는 제일 위에 있는 [nodejs서버](https://github.com/vencax/netlify-cms-github-oauth-provider)를 세팅했다.

서버를 돌려준 다음 
```
➜  netlify-cms-github-oauth-provider (master) ✗ npm start

> netlify-cms-github-oauth-provider@1.0.0 start
> node app.js

gandalf is walkin' on port 3000

```

config의 baseurl을 oauth서버로 세팅한다. 
repo나 media_folder를 커스터마이징해주고, 밑에 collection은 포스팅을 할 때 제목외 요소들(category tag) 등을 에디터에 추가할 수 있다. field widget 타입은 https://www.netlifycms.org/docs/widgets/ 여기서 가져다 쓰면된다. 

이렇게 세팅한뒤 
```bash
npm install netlify-cms-app --save
```
실행시켜주면 구축이 완료된다. `/admin` 페이지를 통해서 로그인후 사용할 수 있다. 

netlify-cms 의 경우 사용감이 꽤 나쁘지 않았다. 실제로 처음에 찾고 있던 2,3 조건이 얼추 만족한다. 바로 바로 github에 커밋이 되고 적용이 된다는 점에서 굉장히 괜찮다.

이미지를 업로드하고 사용하는 부분에서 jekyll-admin보다 훨씬 좋았지만, 역시나 control-v 로 업로드와 이미지 적용까지 되지는 않았다.. 아니 왜.. ㅜ




### (3) Etc

2번째로 스타가 많았던, Prose는 로컬에 구축할때 에러를 거하게 내뿜고 마지막커밋이 3년전이라 접었다. 

온라인 에디터도 존재하였다. 특히 chrome extension으로 존재하는 jekyll Editor가 꽤 괜찮아보였다.

하지만 계정에 꽤 예민한(어떤 흑역사를 생성할지 모르는) 나는, 내 깃헙 계정을 권한을 다른 서비스에서 로그인하려니 뭔가 찝찝했다. give up..



### (4) 돌고돌아.. vscode

대체 뭘써야하는가 만족스러운게 없다. 그나마 `netlify-cms` 가 나았으나, 단축키로 업로드가 안되는건 용납할 수 없다.

진지하게 플랫폼을 다시 옮길까도 생각했다. 의식을 안할때는 상관이 없었는데, 한번 답답하니 미치겠다. 지금 local로 글을 쓰고 있는 내 자신이 실시간으로 한심해진다.

나와 같은 생각을 한 사람이 없을리가 없다는 생각이드는데 내가 못찾는 걸까??

wordpress나 google blog로 옮길까 하다가, 직접 만들어 보는것도 나쁘지 않겠다는 생각이 들었다. hackmd같은 오픈소스를 고쳐서 editor cms 만드는것쯤은 간단하지 않을까..?

개발을 고민하던 중 vscode의 paste image extension을 발견했다..

online을 잠시 내려놓고, offline이지만 이미지 복붙을 더 편하게 할 수 있는 최후의 수단이었다. 

![vscode paste image](/assets/img/post/2021-12-19-06-05-55.png)

해당 extension을 설치한 뒤 아래와 같이 붙여넣기한 이미지가 들어갈 디렉토리를 세팅해주고, 
![vscode setting](/assets/img/post/2021-12-19-06-06-55.png)

paste image단축키를 눌러주면 이미지가 해당 디렉토리에 들어감과 동시에 markdown으로 링크가 걸렸다.

돌고 돌아 vscode라는 갓갓 에디터로 돌아온 기분이다. 사용감은 나쁘지 않지만, 언젠가 시간될때 online으로 작업할 수 있는 editor 서비스를 개발해보면 좋을 것 같다.





