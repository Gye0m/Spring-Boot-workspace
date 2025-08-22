package com.kh.menu.model.dao;

import java.util.HashMap;
import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kh.menu.model.dto.MenuDto.MenuPost;
import com.kh.menu.model.dto.MenuDto.MenuPut;
import com.kh.menu.model.dto.MenuDto.MenuResponse;

@Repository
public class MenuDao {
	
	@Autowired
	private SqlSessionTemplate session;

	public List<MenuResponse> selectMenus(HashMap<String, Object> param) {
		return session.selectList("menumapper.selectMenus", param);
	}

	public int insertMenu(MenuPost menu) {
		return session.insert("menumapper.insertMenu",menu);
	}

	public MenuResponse menuDetail(long id) {
		return session.selectOne("menumapper.menuDetail",id);
	}

	public int updateMenu(MenuPut menu) {
		return session.update("menumapper.updateMenu", menu);
	}

	public int deleteMenu(long id) {
		return session.delete("menumapper.deleteMenu",id);
	}

}








