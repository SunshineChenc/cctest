package com.shangwangding.admin.control;



import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.shangwangding.admin.Access;
import com.shangwangding.admin.dto.Admin;
import com.shangwangding.admin.dto.LogInfo;
import com.shangwangding.admin.service.AdminService;
import com.shangwangding.utils.Constants;
import com.shangwangding.utils.CryptogramUtil;
import com.shangwangding.utils.DateUtil;
import com.shangwangding.utils.SystemUtil;
import com.shangwangding.utils.ValidateUtil;



@Controller
@RequestMapping("/admin")
public class AdminControl {
	
	private static final Logger log = Logger.getLogger(AdminControl.class);

	@Resource
	private AdminService adminService;
	
	@RequestMapping("/login")
	public String intoLogin() {
		
		return "admin/adminLogin";
	}
	
	@RequestMapping("/waitPass")
	public String intoWedderWaitPass(){
		return "admin/adminWaitPass";
	}
	
	@RequestMapping("/loginOut")
	public String loginOut(HttpServletRequest req) {
		
		req.getSession().invalidate();
		
		return "redirect:login";
	}
	
	@RequestMapping("/intoCenter")
	public String intoCenter(HttpServletRequest request){
		return "admin/adminCenter";
		
	}
	
	@RequestMapping("/intoaddClassroom")
	public String intoAddClassroom(){
		return "admin/addClassroom";
	}
	
	/**
	 * 管理员登录处理，登录成功跳转到管理中心，登录失败就返回到登陆页面
	 * @param req
	 * @param resp
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/doLogin")
	public String adminLogin(HttpServletRequest req, HttpServletResponse resp) throws Exception {
		req.setCharacterEncoding("UTF-8");
		String key = (String)req.getSession().getAttribute(Constants.ENCRYPT_CODE);
		String email = ValidateUtil.valiStrIsEmail(SystemUtil.removeAllScriptFromHtml(CryptogramUtil.decrypt(req.getParameter("encryptEmail"), key)));
		String password = CryptogramUtil.decrypt(SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmpty(req.getParameter("encryptPwd"))), key);
		Admin admin = adminService.doGetAdminByEmail(email);
		String alertMessage = "用户名或密码错误";
		if (admin == null) {
			req.setAttribute("e", alertMessage);
			return "admin/adminLogin";
		}
		
		if (admin.getAdminPassword().equals(password)) {
			
			admin.setAdminId(CryptogramUtil.encrypt(admin.getAdminId(), key));
			log.debug("\n\n\n\n\n-----"+admin.toString());
			admin.setAdminEmail(CryptogramUtil.encrypt(admin.getAdminEmail(), key));
			admin.setAdminPassword(CryptogramUtil.encrypt(admin.getAdminPassword(), key));
			admin.setCreateAdminIp(CryptogramUtil.encrypt(admin.getCreateAdminIp(), key));
			req.getSession().setAttribute(Constants.LOGINUSER_SESSION_NAME_ADMIN, admin);
			if (admin.getAdminAccess().toIntValue() == 2){
				return "redirect:intoCenter";
			}else if(admin.getAdminAccess().toIntValue() == 0){
				return "redirect:dataManageAdminCenter";
			}else if(admin.getAdminAccess().toIntValue() == 1){
				return "redirect:contentAdminCenter";
			}
		} else {
			req.setAttribute("e", alertMessage);
			return "admin/adminLogin";
		}
		return null;
	}
	
	/**
	 * 添加管理员
	 * @param request
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/addAdmin")
	@ResponseBody
	public Map<String, Object> addAdmin(HttpServletRequest request) throws Exception{
		Map<String, Object> result = new HashMap<String, Object>();
		Admin admin = getAdmin(request);
		if (admin != null && adminService.doAddAdmin(admin)){
			result.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
			result.put("msg", Constants.AJAX_SUCCESS_MESSAGE);
		}else{
			result.put("code", Constants.AJAX_FAIL_ALERT_CODE);
			result.put("msg", Constants.AJAX_FAIL_MESSAGE);
		}
		return result;
	}
	private Admin getAdmin(HttpServletRequest request){
		
		String key = (String)request.getSession().getAttribute(Constants.ENCRYPT_CODE);
		try {
			String encodeData = request.getParameter("t");
			Map<String, Object> data = CryptogramUtil.decryptAll(encodeData, key);
			String email = SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmail((String)data.get("email")));
			String name = SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmpty((String)data.get("name")));
			String password = SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmpty((String)data.get("password")));
			String rePassword= SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmpty((String)data.get("rePassword")));
			log.debug("\n\n\n\n\n-----pwd1: "+ password+ " pwd2:"+rePassword);
			Access access = Access.getAccess(SystemUtil.removeAllScriptFromHtml(ValidateUtil.valiStrIsEmpty((String)data.get("ac"))));
			if (password.equals(rePassword)){
				Admin admin = new Admin();
				admin.setAdminAccess(access);
				admin.setAdminName(name);
				admin.setAdminPassword(password);
				admin.setAdminEmail(email);
				admin.setCreateAdminIp(SystemUtil.getRequestIp(request));
				admin.setCreateAdminTime(DateUtil.convertCurrentDTTMtoInt());
				log.debug("\n\n\n\n----admin: "+admin.toString());
				return admin;
			}else{
				return null;
			}
		} catch (Exception e) {
			return null;
		}
		
	}
	
	/**
	 * 根据管理员邮箱删除对应管理员
	 * @param requset
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/delAdmin")
	@ResponseBody
	public Map<String, Object> delAdmin (HttpServletRequest requset) throws Exception{
		Map<String, Object> result = new HashMap<String, Object>();
		String key = (String) requset.getSession().getAttribute(Constants.ENCRYPT_CODE);
		String email = ValidateUtil.valiStrIsEmail(SystemUtil.removeAllScriptFromHtml(CryptogramUtil.decrypt(requset.getParameter("email"), key)));
		if (adminService.doDelAdminByEmail(email)){
			result.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
			result.put("msg", Constants.AJAX_SUCCESS_MESSAGE);
		}else{
			result.put("code", Constants.AJAX_FAIL_ALERT_CODE);
			result.put("msg", Constants.AJAX_FAIL_MESSAGE);
		}
		return result;
	}
	
	/**
	 * 检查邮箱是否可用
	 * @param requset
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/checkEmailIsUseful")
	@ResponseBody
	public Map<String, Object> checkEmailIsUseful (HttpServletRequest requset) throws Exception{
		Map<String, Object> result = new HashMap<String, Object>();
		String key = (String) requset.getSession().getAttribute(Constants.ENCRYPT_CODE);
		String email = SystemUtil.removeAllScriptFromHtml(CryptogramUtil.decrypt(requset.getParameter("email"), key));
		Admin admin = adminService.doGetAdminByEmail(email);
		if (admin == null){
			result.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
			result.put("msg", Constants.AJAX_SUCCESS_MESSAGE);
		}else{
			result.put("code", Constants.AJAX_FAIL_ALERT_CODE);
			result.put("msg", "邮箱已存在！");
		}
		return result;
	}
	
	/**
	 * 获取所有管理员信息列表
	 * @param requset
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/getAllAdminlist")
	@ResponseBody
	public Map<String, Object> getAllAdminList (HttpServletRequest requset) throws Exception{
		Map<String, Object> result = new HashMap<String, Object>();
		String key = (String) requset.getSession().getAttribute(Constants.ENCRYPT_CODE);
		List<Admin> adminList = adminService.doGetAllAdminList();
		log.debug("\n\n\n\n----"+adminList.size());
		for (Admin admin : adminList){
			admin.setAdminPassword(CryptogramUtil.encrypt(admin.getAdminPassword(), key));
			admin.setAdminEmail(CryptogramUtil.encrypt(admin.getAdminEmail(), key));
			admin.setAdminId(CryptogramUtil.encrypt(admin.getAdminId(), key));
			admin.setAdminName(CryptogramUtil.encrypt(admin.getAdminName(), key));
			admin.setCreateAdminIp(CryptogramUtil.encrypt(admin.getCreateAdminIp(), key));
		}
		
		if (adminList.size() > 0){
			result.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
			result.put("data", adminList);
		}else{
			result.put("code", Constants.AJAX_FAIL_ALERT_CODE);
			result.put("msg", Constants.AJAX_FAIL_MESSAGE);
		}
		return result;
	}
	
	/**
	 * 日志下载
	 * @param request
	 * @return
	 */
	@RequestMapping("/downLogs")
	public String downLogs(HttpServletRequest request){
		String fileName = ValidateUtil.valiStrIsEmpty(request.getParameter("fileName").trim());
		log.debug("\n\n\n\n-------"+fileName);
		String url = request.getSession().getServletContext().getRealPath(fileName);
		request.setAttribute("url", url);
		return "/admin/downloadLogs";
	}
	
	/**
	 * 获取日志信息
	 * @param request
	 * @return
	 */
	@RequestMapping("/getAllLogInfo")
	@ResponseBody
	public Map<String, Object> getAllLogInfo(HttpServletRequest request){
		String dir =ValidateUtil.valiStrIsEmpty(request.getParameter("dir").trim());
		String url = request.getSession().getServletContext().getRealPath(dir);
		Map<String, Object> resultMap = new HashMap<String, Object>();
		List<LogInfo> list = new ArrayList<LogInfo>();
		log.debug("\n\n\n\n------url"+url);
		File file = new File(url+"\\");
		String test[] = file.list();
		for (String elem : test){
			LogInfo log = new LogInfo();
			File f = new File(url+"\\"+elem);
			long time = f.lastModified();
			log.setLogName(elem);
			log.setTime(DateUtil.formatToDTTMString((int)(time/1000)));
			list.add(log);
		}
		resultMap.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
		resultMap.put("data", list);
		return resultMap;
	}
	
	/**
	 * 删除日志
	 * @param request
	 * @return
	 */
	@RequestMapping("/deleteLog")
	@ResponseBody
	public Map<String, Object> deleteLog(HttpServletRequest request){
		Map<String, Object> result = new HashMap<String,Object>();
		String dir =ValidateUtil.valiStrIsEmpty(request.getParameter("dir").trim());
		String fileName = ValidateUtil.valiStrIsEmpty(request.getParameter("fileName")).trim();
		String url = request.getSession().getServletContext().getRealPath(dir);
		File file = new File(url+"\\"+fileName);
		log.debug("\n\n\n\n\n------file: "+url+"\\"+fileName);
		boolean flag = false;
		if (file.exists() && file.isFile()){
			flag= file.delete();
			log.debug("\n\n\n\n\n------flag: "+flag);
		}
		if (flag){
			result.put("code", Constants.AJAX_SUCCESS_ALERT_CODE);
		}else {
			result.put("code", Constants.AJAX_FAIL_ALERT_CODE);
		}
		return result;
	}
}
