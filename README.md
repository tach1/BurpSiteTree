# BurpSiteTree
HTTPリクエストをTSV形式でクリップボードにコピーするBurp Extensionです。

## Features
- JSONパラメータの各値をJSONPathに展開してコピーします。
- 複数のリクエストを選択してまとめてコピーできます。
- 日本語はUTF-8を想定しています。
- シンプルなので各自カスタマイズしてください。

## Usage
コピーしたいリクエストを選択して右クリックします。

## Build
```
git clone https://github.com/tach1/BurpSiteTree.git
cd BurpSiteTree
gradlew fatjar

-> build/libs/BurpSiteTree-all.jar
```
## Lisense
[MIT](https://github.com/tach1/BurpSiteTree/blob/main/LICENSE)