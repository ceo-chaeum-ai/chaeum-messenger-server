-- morph:nontransactional
-- Single-user reads (GetSubject) filter on TargetID and GroupID, and the
-- membership queries join on TargetID. Unique because the view groups by these
-- columns.
-- CONCURRENTLY cannot run inside a transaction, so this must be the only
-- statement in the file.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_userattributeview_targetid_groupid_targettype ON UserAttributeView (TargetID, GroupID, TargetType);
