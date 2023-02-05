package org.zerock.club.service;

import org.zerock.club.dto.NoteDTO;

public interface NoteService {

    Long register(NoteDTO noteDTO);

    NoteDTO get(Long num);

    void modify(NoteDTO noteDTO);

}
