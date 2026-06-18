// Vulnerable: VUL-CVE-2022-27404
/* value -(N+1) requests information on index N */
    if ( face_instance_index < 0 )
      face_index--;
// --- sfwoff2.c ---
    *num_faces = woff2.num_fonts;
    /* value -(N+1) requests information on index N */
    if ( *face_instance_index < 0 )
      face_index--;
