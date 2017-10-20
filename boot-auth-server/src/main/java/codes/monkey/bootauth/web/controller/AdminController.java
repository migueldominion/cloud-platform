package codes.monkey.bootauth.web.controller;

import codes.monkey.bootauth.persistence.dao.UserRepository;
import codes.monkey.bootauth.persistence.model.User;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AdminController {

	private final Logger LOGGER = LoggerFactory.getLogger(getClass());
	
    @Autowired
    UserRepository userRepository;

    @RequestMapping(value = "/admin",method = RequestMethod.GET)
    public String productsList(Model model){
    	List<User> users = userRepository.findAll();
    	
        model.addAttribute("users", users);
        
        return "admin";
    }

}