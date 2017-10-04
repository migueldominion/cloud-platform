package codes.monkey.bootauth.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import codes.monkey.bootauth.persistence.dao.PrivilegeRepository;
import codes.monkey.bootauth.persistence.dao.RoleRepository;
import codes.monkey.bootauth.persistence.dao.UserRepository;
import codes.monkey.bootauth.persistence.model.Privilege;
import codes.monkey.bootauth.persistence.model.Role;
import codes.monkey.bootauth.persistence.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

	private boolean alreadySetup = false;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PrivilegeRepository privilegeRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	// API

	@Override
	@Transactional
	public void onApplicationEvent(final ContextRefreshedEvent event) {
		/*
		 * Note how we’re using an alreadySetup flag to determine if the setup needs to
		 * run or not. This is simply because, depending on how many contexts you have
		 * configured in your application – the ContextRefreshedEvent may be fired
		 * multiple times. And we only want the setup to be executed once.
		 */
		if (alreadySetup) {
			return;
		}

		// == create initial privileges
		final Privilege readPrivilege = createPrivilegeIfNotFound("READ_PRIVILEGE");
		final Privilege writePrivilege = createPrivilegeIfNotFound("WRITE_PRIVILEGE");
		final Privilege passwordPrivilege = createPrivilegeIfNotFound("CHANGE_PASSWORD_PRIVILEGE");

		// == create initial roles
		final List<Privilege> adminPrivileges = Arrays.asList(readPrivilege, writePrivilege, passwordPrivilege);
		final List<Privilege> userPrivileges = Arrays.asList(readPrivilege, passwordPrivilege);
		final List<Privilege> readerPrivileges = Arrays.asList(readPrivilege);

		createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);
		createRoleIfNotFound("ROLE_USER", userPrivileges);
		createRoleIfNotFound("ROLE_READER", readerPrivileges);

		final Role adminRole = roleRepository.findByName("ROLE_ADMIN");
		final Role userRole = roleRepository.findByName("ROLE_USER");
		final Role readerRole = roleRepository.findByName("ROLE_READER");

		final User user = new User();
		user.setFirstName("admin");
		user.setLastName("admin");
		user.setPassword(passwordEncoder.encode("admin"));
		user.setEmail("admin@admin.com");
		user.setRoles(Arrays.asList(adminRole));
		user.setEnabled(true);
		userRepository.save(user);

		final User user1 = new User();
		user1.setFirstName("user");
		user1.setLastName("user");
		user1.setPassword(passwordEncoder.encode("user"));
		user1.setEmail("user@user.com");
		user1.setRoles(Arrays.asList(userRole));
		user1.setEnabled(true);
		userRepository.save(user1);

		final User user2 = new User();
		user2.setFirstName("reader");
		user2.setLastName("reader");
		user2.setPassword(passwordEncoder.encode("reader"));
		user2.setEmail("reader@reader.com");
		user2.setRoles(Arrays.asList(readerRole));
		user2.setEnabled(true);
		userRepository.save(user2);

		alreadySetup = true;
	}

	@Transactional
	private final Privilege createPrivilegeIfNotFound(final String name) {
		Privilege privilege = privilegeRepository.findByName(name);
		if (privilege == null) {
			privilege = new Privilege(name);
			privilegeRepository.save(privilege);
		}
		return privilege;
	}

	@Transactional
	private final Role createRoleIfNotFound(final String name, final Collection<Privilege> privileges) {
		Role role = roleRepository.findByName(name);
		if (role == null) {
			role = new Role(name);
			role.setPrivileges(privileges);
			roleRepository.save(role);
		}
		return role;
	}

}