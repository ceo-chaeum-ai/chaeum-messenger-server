-- morph:nontransactional
-- Single-channel reads (GetSubject) filter on TargetID and GroupID. Unique
-- because the view groups by these columns.
-- CONCURRENTLY cannot run inside a transaction, so this must be the only
-- statement in the file.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_channelattributeview_targetid_groupid_targettype ON ChannelAttributeView (TargetID, GroupID, TargetType);
