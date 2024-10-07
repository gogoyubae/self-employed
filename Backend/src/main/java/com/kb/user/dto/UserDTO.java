package com.kb.user.dto;



import com.kb.member.dto.Member;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class UserDTO {
    private String id; 			// id=username
    private String password;	// password
    private String name;        // 사용자이름
    private String email;       // 이메일

    public Member toMember() {
        return Member.builder().id(id).password(password).name(name).email(email).build();
    }
}
