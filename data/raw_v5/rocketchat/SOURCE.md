# Rocket.Chat — test_v5 hold-out 후보 추출 기록

- Repository: https://github.com/RocketChat/Rocket.Chat
- Tag: `8.9.0` (GitHub releases/latest, 2026-10-05) — commit `057a927d903c83b5d61cf236d650c4500ebb4b66`
- Clone: `datasets/blade/raw/opensource/RocketChat_Rocket.Chat/` (`--depth 1 --filter=blob:none --sparse`). 읽기만 했고 빌드·실행·의존성 설치 없음. LLM API 호출 없음.
- sparse-checkout 경로: `apps/meteor/app/api`(8.9.0에는 없음), `apps/meteor/app/authorization`, `apps/meteor/app/lib/server`, `apps/meteor/server/lib`, `apps/meteor/server/methods`, `apps/meteor/app/utils`, `packages/rest-typings/src` + 실제 위치 보정 `apps/meteor/server/api`, `apps/meteor/server/meteor-methods`, `apps/meteor/server/services/authorization`(없음)·`team`, `apps/meteor/lib/rooms`, `packages/authorization/src`, `packages/models/src/models`.
  - 8.9.0에서 REST v1 라우트는 `apps/meteor/server/api/v1/*.ts`, 인가 서비스는 `packages/authorization/src/`(canAccessRoom·canReadRoom·Authorization.hasPermission)에 있다.
- 산출: `candidates.jsonl` 163건, 생성 스크립트 `extract_rocketchat.py`(`python -I extract_rocketchat.py build|validate`).

## 라이선스

루트 `LICENSE`(SPDX: MIT, 1,686 bytes) 원문 요지:

> All content that resides under the "apps/meteor/ee/" and "ee/" directories of this repository, if that directory exists, is licensed under the license defined in "apps/meteor/ee/LICENSE". … Content outside of the above-mentioned directories or restrictions above is available under the MIT (Expat) license as defined below.

`apps/meteor/ee/LICENSE`("The Rocket.Chat Enterprise Edition (EE) license"): 유효한 Enterprise Edition 구독 하에서만 프로덕션 사용 가능. 따라서 **`apps/meteor/ee/`, `ee/` 아래 코드는 전부 제외**했다(sparse-checkout에서 받지 않았고 LICENSE 파일만 `git show`로 읽음).

- ee 제외 결과: `apps/meteor/ee/server/api/v1/`(omnichannel EE, engagementDashboard, abac, mcp 등) 라우트는 조사·추출하지 않았다. 추출된 163건 중 ee 경로를 source_locations·controller_text에 포함한 레코드 0건(validate가 `/ee/` 경로 부재를 assert).
- 발췌한 `packages/authorization/src/canAccessRoom.ts`는 MIT 영역이다. 이 파일이 `License.hasModule('abac')`를 호출하지만 코드 자체는 core(MIT)이며 ABAC 분기는 라벨 판단에서 "라이선스·설정이 없으면 이전 동작" 경로(구독 행)만 근거로 썼다.

## 인가 구조 요약 (8.9.0)

- 라우트 등록: `API.v1.get/post/put/delete(name, options, handler)`(신규), 체인형 `API.v1.get(...).post(...)`, 레거시 `API.v1.addRoute(name, options, {get(){..}})`, `im.ts`는 `.post('im.x', xEndpointsProps, xAction('im.x'))` 형태(`dm.*`는 동일 핸들러의 별칭이라 `im.*`만 수록).
- 옵션: `authRequired`(x-user-id/x-auth-token 또는 PAT 검증, `authenticationMiddlewareForHono`), `authOrAnonRequired`(설정 `Accounts_AllowAnonymousRead`), `permissionsRequired`(`permissionsMiddleware` → `checkPermissionsForInvocation` → `hasAllPermissionAsync`/`hasAtLeastOnePermissionAsync`), `twoFactorRequired`.
- 권한: `Authorization.hasPermission(user, permissionId, scope?)` — 전역 역할 + (scope=rid면) 구독(`Subscriptions`)의 방 역할(owner·moderator·leader)을 합쳐 `Permissions.roles`와 대조. 기본 매핑은 `apps/meteor/server/lib/authorization/constant/permissions.ts`(예: `edit-room`=admin/owner/moderator, `delete-d`=admin, `view-all-teams`=admin, `manage-own-*-integrations`=admin, `leave-p`·`start-discussion`·`create-personal-access-tokens`=user 포함).
- 방 접근: `canAccessRoomAsync`(`packages/authorization/src/canAccessRoom.ts`) = OR 검증기 체인: 공개 채널(`t:'c'`)→`view-c-room` 권한(익명은 설정), 팀 소속 공개 채널→공개 팀이면 `view-c-room`, 비공개 팀이면 `TeamMember` 행; `_validateIfAlreadyJoined`→`Subscriptions.countByRoomIdAndUserId` 구독 행 AND (`view-joined-room` OR `view-{t}-room`); discussion→상위 방; livechat. `canReadRoom` = canAccessRoom AND (공개 채널은 `preview-c-room` OR 구독).
- 그룹 헬퍼: `findPrivateGroupByIdOrName`(groups.ts)은 `t==='p'`만 허용 + `canAccessRoomAsync` → 비공개 방이므로 사실상 요청자 구독 행 필요. `findDirectMessageRoom`(im.ts)은 `t==='d'` 방만 반환하고 각 핸들러가 `canAccessRoomIdAsync`로 구독을 요구. `findChannelByIdOrName`(channels.ts)·`findRoomByIdOrName`(rooms.ts)은 접근 검사가 없고 핸들러·메서드(saveRoomSettings=`edit-room`, removeUserFromRoomMethod=`remove-user`, executeArchiveRoom=`archive-room`, eraseRoom=`delete-{t}`, addRoomModerator=`set-moderator` 등 방 범위 권한)가 결정.
- 팀: `Team` 서비스(`apps/meteor/server/services/team/service.ts`)가 `TeamMember.findOneByUserIdAndTeamId`로 구성원 조회, `view-all-teams`(팀 방 범위)로 우회. 공개 팀(`TeamType.PUBLIC`)은 listRooms·info에서 구성원 조건이 사라진다.
- 사용자: `isUserFromParams`(본인 판정) + `edit-other-user-*`/`logout-other-user` 권한으로 타인 대상 허용(owner_or_admin 패턴). `users.update`는 `validateUserData`(본인 OR edit-other-user-info) + `validateUserEditing`(필드·설정별 권한).
- 통합(integrations): `manage-{incoming|outgoing}-integrations`면 전체, 아니면 `_createdBy._id === userId` AND `manage-own-*-integrations`.

## 수록 범위와 제외

- 수록 파일: groups.ts, im.ts, teams.ts, users.ts, rooms.ts, subscriptions.ts, chat.ts, integrations.ts, oauthapps.ts, e2e.ts, permissions.ts, roles.ts, settings.ts, channels.ts, misc.ts(me, pw.getPolicy), default/info.ts(info), ApiClass.ts(login).
- 제외: `apps/meteor/ee/**`(EE 라이선스), omnichannel/livechat·apps·federation·banners·moderation·cloud·mailer·video-conference·media-calls·calendar·push·import·ldap·saml·assets·custom-*·commands·autotranslate·webdav·ai-search·stats·instances·invites(목표 라벨 예시가 아니거나 외부 시스템·설정 의존), `dm.*` 별칭(im.*와 동일 핸들러), `method.call/:method`(임의 메서드 프록시), `spotlight`·`directory`(검색), `rooms.get`·`rooms.join`·`channels.join`·`chat.update`·`chat.postMessage`·`im.create`·`im.blockUser`(호출 메서드 본문을 시간 내 확인하지 못함), `users.getAvatar`(리다이렉트), `groups.setDescription/setPurpose/setAnnouncement/setCustomFields/setEncrypted`·`oauth-apps.create/update`·`teams.addRooms/removeRoom/updateRoom/convertToChannel`(같은 패턴 중복이라 미수록).
- ee 제외 건수: ee 라우트는 조사하지 않았으므로 "ee 때문에 떨어진 후보" 0건(조사 범위 밖). core 후보 중 ee 코드가 인가 경로에 끼어 제외한 건 0건.

## 초안 라벨 집계 (163건)

| draft_label | 건수 |
|---|---:|
| role_required | 56 |
| manual_review_required | 37 |
| owner_match | 27 |
| membership_required | 26 |
| owner_or_admin | 11 |
| public | 6 |
| tenant_match | 0 |

membership_required(26): groups.info/messages/history/files/roles/moderators/members/online/close/open/leave, im.close/open/files/members/messages/history/leave, teams.members/listChildren/leave, rooms.leave, channels.leave/close/open, chat.starMessage.
owner_or_admin(11): users.setAvatar/resetAvatar/setPreferences/setStatus/logout/resetE2EKey/resetTOTP, integrations.get/update/remove/history.

## 불확실한 항목 (검수자 참고)

1. **비공개 방 접근 = 구독 행**: `_validateIfAlreadyJoined`는 구독 행 AND (`view-joined-room` OR `view-p-room`/`view-d-room`) 이다. 기본적으로 user 역할이 `view-p-room`·`view-d-room`을 가지므로 기능 권한으로 보고 membership_required로 두었다. discussion(`prid`) 방은 상위 방 접근으로도 통과한다(confidence 0.7~0.8).
2. **groups.members**: broadcast 방이면 `view-broadcast-member-list` AND. 0.6.
3. **im.delete**: (구독 OR view-room-administration) 뒤에 eraseRoom이 `delete-d`(기본 admin만)를 요구 → role_required 0.65로 두었다. 보류 또는 membership 가능.
4. **teams.info / listRooms / listRoomsOfUser**: 공개 팀은 구성원 조건이 없어 보류로 두었다. 비공개 팀만 보면 membership_required(members와 동일).
5. **teams.leave, channels.close/open, im.close/open, rooms.favorite/saveNotification/saveDraft/open, chat.ignoreUser, chat.starMessage**: "요청 대상 방·팀의 본인 구독 행"이 조건이라 membership_required와 owner_match 경계다. 요청이 대상 그룹을 지정하고 (요청자, 그룹) 구독 행을 조회하면 membership, 본인 구독의 플래그·상태만 바꾸면 owner_match로 나눴다. 검수에서 일관되게 재조정 필요.
6. **integrations.get/update/remove/history**: 소유자 분기에도 `manage-own-*-integrations`(기본 admin만) 권한이 AND로 붙는다. owner_or_admin 0.6; 보류 또는 role_required 가능.
7. **users.setAvatar/resetAvatar/setStatus/deleteOwnAccount/register/forgotPassword**: 설정(`Accounts_AllowUserAvatarChange` 등)에 의존하는 분기가 있다. 설정 의존을 중시하면 보류.
8. **users.update, users.createToken, users.listTeams, users.info**: 필드·파라미터·환경변수 의존 복합 조건으로 보류.
9. **canAccessRoom 기반 "아무 방" 엔드포인트(rooms.info, chat.getMessage 등 17건)**: 방 유형별 OR 분기라 보류로 두었다(검수 규약 G6). 사람 검수에서 "방 접근 권한"을 하나의 정책으로 인정하면 재라벨 대상.
10. **rooms.createDiscussion**(0.55): `start-discussion`은 기본 user 권한이라 실질 조건이 약하다. 상위 방 접근 검사는 발췌 범위 밖(createDiscussion 내부 이후 로직)이라 확인하지 못했다.
11. `oas_operation`은 라우트 옵션의 query/body 검증기 이름과 핸들러의 파라미터 사용을 보고 수작업으로 만든 최소 명세(`oas_status: generated`). rest-typings 주석에 권한 문구가 없어 `permission_doc`은 모두 "".
