# ots_federation/models/geochat.py
# Bundled from taky.cot.models.geochat (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester). Bundled to decouple from taky.

import enum

from lxml import etree
from dateutil.parser import isoparse

from .errors import UnmarshalError
from .detail import Detail

ALL_CHAT_ROOMS = "All Chat Rooms"
GEOCHAT_TAGS = set(["__chat", "remarks", "link"])


class ChatParents(enum.Enum):
    ROOT = "RootContactGroup"
    TEAM = "TeamGroups"


class GeoChat(Detail):
    """GeoChat message — all-chat-rooms broadcast or direct/group message."""

    def __init__(self, elm):
        super().__init__(elm)

        self.chatroom = None
        self.chat_parent = None
        self.group_owner = False

        self.src_uid = None
        self.src_cs = None
        self.src_marker = None
        self.message = None
        self.message_ts = None

        self.dst_uid = None
        self.dst_team = None

    def __repr__(self):
        if self.broadcast:
            return '<GeoChat src="%s", dst="%s", msg="%s">' % (
                self.src_cs, ALL_CHAT_ROOMS, self.message,
            )
        if self.dst_team:
            return '<GeoChat src="%s", dst="%s", msg="%s">' % (
                self.src_cs, self.dst_team, self.message,
            )
        return '<GeoChat src="%s", dst_uid="%s", msg="%s">' % (
            self.src_cs, self.dst_uid, self.message,
        )

    @property
    def broadcast(self):
        return self.chatroom == ALL_CHAT_ROOMS

    @staticmethod
    def is_type(tags):
        return GEOCHAT_TAGS.issubset(tags)

    @staticmethod
    def from_elm(elm):
        if elm.tag != "detail":
            raise UnmarshalError("Cannot create GeoChat from %s" % elm.tag)

        chat = elm.find("__chat")
        chatgrp = None
        if chat is not None:
            chatgrp = chat.find("chatgrp")
        remarks = elm.find("remarks")
        link = elm.find("link")

        if None in [chat, chatgrp, remarks, link]:
            raise UnmarshalError("Detail does not contain GeoChat")

        gch = GeoChat(elm)
        gch.chat_parent = chat.get("parent")
        gch.group_owner = chat.get("groupOwner") == "true"
        gch.src_uid = link.get("uid")
        gch.src_cs = chat.get("senderCallsign")
        gch.src_marker = link.get("type")

        gch.chatroom = chat.get("chatroom")
        if gch.chat_parent == ChatParents.TEAM.value:
            # dst_team is now a plain string — no enum construction.
            gch.dst_team = gch.chatroom or ""
        elif gch.chatroom != ALL_CHAT_ROOMS:
            gch.dst_uid = chat.get("id")

        gch.message = remarks.text
        gch.message_ts = isoparse(remarks.get("time")).replace(tzinfo=None)

        return gch

    @property
    def as_element(self):
        if self.elm is not None:
            return self.elm

        if self.broadcast:
            dst_uid = ALL_CHAT_ROOMS
        elif self.dst_team:
            dst_uid = self.dst_team  # already a plain string
        else:
            dst_uid = self.dst_uid

        detail = etree.Element("detail")
        chat = etree.Element(
            "__chat",
            attrib={
                "parent": self.chat_parent,
                "groupOwner": "true" if self.group_owner else "false",
                "chatroom": self.chatroom,
                "id": dst_uid,
                "senderCallsign": self.src_cs,
            },
        )
        chatgroup = etree.Element(
            "chatgrp",
            attrib={"uid0": self.src_uid, "uid1": dst_uid, "id": dst_uid},
        )
        chat.append(chatgroup)
        detail.append(chat)

        link = etree.Element(
            "link",
            attrib={"uid": self.src_uid, "type": self.src_marker, "relation": "p-p"},
        )
        detail.append(link)

        rmk_src = f"BAO.F.ATAK.{self.src_uid}"
        remarks = etree.Element(
            "remarks",
            attrib={
                "source": rmk_src,
                "to": dst_uid,
                "time": self.message_ts.isoformat(timespec="milliseconds") + "Z",
            },
        )
        remarks.text = self.message
        detail.append(remarks)

        return detail
