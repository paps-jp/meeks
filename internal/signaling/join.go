package signaling

import (
	"encoding/json"

	"meeks/internal/iplog"
	"meeks/internal/store"
)

// Join approval protocol (all messages carry a JSON "data" object):
//
//	claim        {create, inboxPub} key holder registers/refreshes the room;
//	                                 create=true only succeeds for a new room
//	join-request {name, pub}        applicant without the key asks to join
//	join-approve {id, pub, wrap}    a member hands over the room key wrapped
//	                                 for the applicant's public key
//	join-reject  {id}
//	join-done    {id}               applicant got the key; forget the request
//	join-message {id, msgId, data}  encrypted message on a pending request,
//	                                 from the applicant or a member
//
// Requests are stored, so they survive while nobody is online: members see
// them when they next connect, and applicants receive the approval when
// they next connect.
//
// The server cannot tell members from applicants (it never sees the key), so
// a connection that submitted a request may not approve or reject any.

type claimData struct {
	Create   bool   `json:"create"`
	InboxPub string `json:"inboxPub"`
}

type joinData struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Pub   string `json:"pub"`
	Wrap  string `json:"wrap"`
	MsgID string `json:"msgId"`
	Data  string `json:"data"`
}

func (h *Hub) handleJoin(c *client, m inbound) {
	st := h.cfg.Store
	switch m.Type {
	case "claim":
		var d claimData
		json.Unmarshal(m.Data, &d)
		hadInbox := st.InboxPub(c.room) != ""
		ok := st.Claim(c.room, d.Create, d.InboxPub)
		if ok && !d.Create && !hadInbox && st.InboxPub(c.room) != "" {
			// A room created before inbox keys existed just got one: tell
			// waiting applicants they can now send messages.
			defer h.broadcastRequests(c.room)
		}
		out := outbound{Type: "claim-result", OK: &ok}
		if ok {
			out.Requests = st.Pending(c.room)
			out.InboxPub = st.InboxPub(c.room)
		}
		c.enqueue(mustJSON(out))

	case "join-request":
		var d joinData
		if json.Unmarshal(m.Data, &d) != nil {
			return
		}
		req, err := st.Submit(c.room, d.Name, d.Pub)
		if err != nil {
			c.enqueue(mustJSON(outbound{Type: "join-status", Error: err.Error()}))
			return
		}
		h.mu.Lock()
		c.reqID = req.ID
		h.mu.Unlock()
		if h.cfg.IPLog != nil {
			h.cfg.IPLog.Log(iplog.Entry{
				Event: iplog.EventJoinReq, IP: c.ip, Port: c.port,
				Room: iplog.RoomHash(c.room), Peer: c.id,
			})
		}
		c.enqueue(mustJSON(outbound{Type: "join-status", Request: &req, InboxPub: st.InboxPub(c.room)}))
		if req.Status == store.StatusPending {
			h.broadcastRequests(c.room)
		}

	case "join-approve", "join-reject":
		if h.isApplicant(c) {
			return
		}
		var d joinData
		if json.Unmarshal(m.Data, &d) != nil {
			return
		}
		var req store.Request
		var err error
		if m.Type == "join-approve" {
			req, err = st.Approve(c.room, d.ID, d.Pub, d.Wrap)
		} else {
			req, err = st.Reject(c.room, d.ID)
		}
		if err != nil {
			return // already decided by another member, or expired
		}
		h.toApplicant(c.room, req)
		h.broadcastRequests(c.room)

	case "join-message":
		var d joinData
		if json.Unmarshal(m.Data, &d) != nil {
			return
		}
		h.mu.Lock()
		allowed := c.reqID == "" || c.reqID == d.ID // members, or the applicant itself
		h.mu.Unlock()
		if !allowed {
			return
		}
		msg, err := st.AddMessage(c.room, d.ID, d.MsgID, d.Data)
		if err != nil {
			c.enqueue(mustJSON(outbound{Type: "join-message-error", ID: d.ID, Error: err.Error()}))
			return
		}
		h.toRoom(c.room, mustJSON(outbound{Type: "join-message", ID: d.ID, Message: &msg}))

	case "join-done":
		var d joinData
		if json.Unmarshal(m.Data, &d) != nil {
			return
		}
		h.mu.Lock()
		mine := c.reqID != "" && c.reqID == d.ID
		if mine {
			c.reqID = "" // now a member: may approve others
		}
		h.mu.Unlock()
		if mine {
			st.Done(c.room, d.ID)
		}
	}
}

func (h *Hub) isApplicant(c *client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return c.reqID != ""
}

func (h *Hub) toRoom(roomID string, msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.rooms[roomID] {
		p.enqueue(msg)
	}
}

// broadcastRequests sends the current pending list to everyone in the room;
// clients without the key ignore it.
func (h *Hub) broadcastRequests(roomID string) {
	h.toRoom(roomID, mustJSON(outbound{
		Type: "join-requests", Requests: h.cfg.Store.Pending(roomID), InboxPub: h.cfg.Store.InboxPub(roomID),
	}))
}

// toApplicant delivers a decision to the applicant if it is connected.
func (h *Hub) toApplicant(roomID string, req store.Request) {
	msg := mustJSON(outbound{Type: "join-status", Request: &req})
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.rooms[roomID] {
		if p.reqID == req.ID {
			p.enqueue(msg)
		}
	}
}
