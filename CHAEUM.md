# 채움메신저 서버

이 저장소는 [Mattermost](https://github.com/mattermost/mattermost) 서버 v11.1.1 을 채움AI 가 고친 것입니다. Mattermost, Inc. 와는 관계가 없으며, 고친 판은 「채움메신저」라는 이름으로 제공합니다.

- `upstream` 갈래: Mattermost 원본 v11.1.1
- `chaeum` 갈래: 원본에 아래 고침을 더한 것

라이선스는 원본과 같습니다(LICENSE.txt, 서버 소스는 AGPL-3.0). 문의: support@chaeumai.com

## 고친 것 (2026-11-24)

| 자리 (`server/` 아래) | 내용 |
|---|---|
| `channels/store/encryptlayer` | 저장 암호화. 글 본문, 붙임 카드, 초안, 예약 글, 파일 이름과 파일에서 뽑은 본문을 DB 에 넣기 직전에 암호화하고 읽은 직후에 풉니다(AES-256-GCM, 달마다 다른 열쇠). 첨부 파일은 파일마다 열쇠를 따로 뽑아 64KB 토막으로 암호화합니다. 달 열쇠는 바깥의 열쇠 보관 서버(OpenBao 등 Vault 호환 transit)가 감싸 줍니다. 암호화 전에 쌓인 글과 파일을 옮기는 기능이 들어 있습니다. |
| `channels/chaeumsearch` | 암호화하면 DB 가 검색하지 못하므로, 검색을 따로 도는 검색 프로그램에 넘기는 엔진입니다. 옛 달의 글은 서버가 풀어서 훑습니다. `searchproto` 는 그 프로그램과 주고받는 규약입니다. |
| `channels/store/layer_generators` | 암호화 층을 만드는 생성 틀 |
| `channels/app/platform/service.go`, `channels/store/sqlstore` | 위 기능을 끼우는 줄, 길이 검사 |
| `public/model/config.go` | 기본 사이트 이름 |
| `i18n/ko.json`, `../webapp/channels/src/i18n/ko.json` | 한국어 화면 낱말 「채널」을 「대화방」으로 바꿨습니다(2026-11-25). 시스템 콘솔 글과 `@channel` 같은 명령어 낱말은 그대로입니다. |

## 만들기

```
cd server && go work init && go work use . ./public
go build -o ../bin/mattermost ./cmd/mattermost
go test ./channels/store/encryptlayer/ ./channels/chaeumsearch/...
```

## 설정 (환경 변수)

- `CHAEUM_ENC_KEY_ADDR`, `CHAEUM_ENC_KEY_TOKEN_FILE`, `CHAEUM_ENC_KEY_NAME`: 열쇠 보관 서버 주소(https), 토큰 파일, transit 열쇠 이름. 주소가 없으면 암호화하지 않습니다. 암호화한 적이 있는 DB 에서 주소 없이 띄우려면 `CHAEUM_ENC_OFF=1` 이 필요합니다.
- `CHAEUM_ENC_MIGRATE=1`: 암호화 전에 쌓인 글과 파일을 뒤에서 암호문으로 옮깁니다.
- `CHAEUM_SEARCH_SOCKET`: 검색 프로그램의 유닉스 소켓. 함께 `MM_SQLSETTINGS_DISABLEDATABASESEARCH=true` 를 줍니다. 소켓이 없으면 검색 결과만 비고 나머지는 그대로 동작합니다.
