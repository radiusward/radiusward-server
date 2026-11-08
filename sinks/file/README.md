# sink-file

`sink.<name>.type=file`: JSON lines in `dir` (`{"type":"event",…}`, `{"type":"session",…}`), rotated at
`max.file.size`, transactional per member (position file written after fsync; an unconfirmed tail is cut off on
open). Archive and reference implementation for plug-in authors.
