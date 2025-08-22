package com.kh.menu.model.service;

import java.util.HashMap;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kh.menu.model.dao.MenuDao;
import com.kh.menu.model.dto.MenuDto;
import com.kh.menu.model.dto.MenuDto.MenuPost;
import com.kh.menu.model.dto.MenuDto.MenuPut;
import com.kh.menu.model.dto.MenuDto.MenuResponse;

@Service
public class MenuService {
	
	@Autowired
	private MenuDao dao;
	
	public List<MenuResponse> selectMenus(HashMap<String, Object> param) {
		return dao.selectMenus(param);
	}

	public int insertMenu(MenuPost menu) {
		return dao.insertMenu(menu);
	}

	public MenuResponse menuDetail(long id) {
		return dao.menuDetail(id);
	}

	public int updateMenu(MenuPut menu) {
		return dao.updateMenu(menu);
	}

	public int deleteMenu(long id) {
		return dao.deleteMenu(id);
	}
	

}








