from rocketchat_API.APISections.base import RocketChatBase


class RocketChatE2E(RocketChatBase):
    def e2e_updateKey(self, userid, room_id, key, **kwargs):
        return self.call_api_post(
            "e2e.updateGroupKey", uid=userid, rid=room_id, key=key, kwargs=kwargs
        )
    def e2e_fetchMyKeys(self, **kwargs):
        return self.call_api_post(
            "e2e.fetchMyKeys", kwargs=kwargs
        )

