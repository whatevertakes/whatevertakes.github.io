# WT 인프라 지도 데이터

`/ko/research/infra-map/` 페이지가 이 폴더의 YAML을 읽어 만들어집니다. 화면 코드는 `src/pages/ko/research/infra-map/index.astro`, 스키마는 `src/content.config.ts`, 참조 검사와 변환은 `src/lib/infra-data.ts`에 있습니다.

## 공개 규칙

- **공개 자료만 넣습니다.** 이 저장소와 사이트는 공개입니다.
- **미공개 취약점, 탐색 중인 후보, 신고 대기 중인 내용은 절대 넣지 않습니다.** 그런 기록은 팀의 비공개 저장소에만 둡니다.
- 사건과 기업 정보에는 출처 링크를 답니다. 확인되지 않은 보도는 `status: reported`, 당사자가 부인한 것은 `denied`로 표시합니다.

## 구조

| 경로 | 내용 | 참조 |
|---|---|---|
| `areas.yaml` | 인프라 16개 영역. ID는 문자열 `"1"`~`"16"` | `oss`, `links` |
| `links.yaml` | 영역 패널의 외부 DB 바로가기 | |
| `oss/<id>.yaml` | 오픈소스·제품 | `areas` |
| `vulns/<CVE ID>.yaml` | 취약점. `list`가 `base`면 영역의 기본기 목록, `recent`면 최신 실제 악용(KEV) 목록, `none`이면 사건에서만 참조 | `areas` |
| `incidents/<연도>-<이름>.yaml` | 보안 사건. `recent: true`면 영역 패널의 최신 상자에 표시 | `areas`, `vulns` |
| `companies/<id>.yaml` | 기업. 서비스→영역 연결, 바운티 채널, 선택 항목 `deep`(16개 영역 해부) | `areas` |
| `usage/<company>__<oss>.yaml` | 기업이 그 오픈소스를 쓴다는 공개 근거와 신뢰도 | `companies`, `oss` |

파일 이름(확장자 제외)이 그 항목의 ID입니다.

## 추가하는 법

1. 브랜치를 만들고 YAML 파일을 추가하거나 고칩니다.
2. `npm run build`로 확인합니다. 스키마가 틀리거나 없는 ID를 참조하면 빌드가 실패하고 어느 파일이 문제인지 알려 줍니다.
3. PR을 엽니다. PR마다 같은 빌드 검사가 돕니다.

예: 새 KEV 항목은 `vulns/`에 파일 하나를 추가합니다.

```yaml
summary: 한 줄 요약
areas: ["6"]
list: recent
kev: { date: "2026-11-24", ransomware: false }
cvss: { score: 9.8, version: "3.1", source: CVE 레코드(cvelistV5) }
```

CVSS 점수는 CVE 공식 레코드(github.com/CVEProject/cvelistV5)에서 가져오고, 3.1 → 3.0 → 4.0 순으로 고릅니다.

## KEV 자동 동기화

`.github/workflows/kev-sync.yml`이 매일 07:17(KST)에 돕니다.

1. CISA KEV 최신본(github.com/cisagov/kev-data 미러)에서 `scripts/kev-sync-state.json`의 기준일 이후 새로 등재된 항목을 찾습니다.
2. 항목마다 CVE 공식 레코드에서 CVSS 점수를 가져오고, `scripts/kev-area-rules.json` 규칙으로 영역을 정해 `vulns/`에 파일을 만듭니다(`list: recent`).
3. 사이트 빌드가 통과하면 `kev-sync/auto` 브랜치로 PR을 엽니다. 규칙에 맞지 않는 항목은 파일을 만들지 않고 PR 설명에 "영역 분류 필요"로 남깁니다.

사람이 할 일: 자동 분류된 영역 확인, 영어 원문 `summary`를 한국어 한 줄 요약으로 바꾸기, 병합.
수동 실행: Actions → KEV sync → Run workflow. 로컬 실행: `node scripts/kev-sync.mjs`.
