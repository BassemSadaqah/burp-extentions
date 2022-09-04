from burp import IBurpExtender               
from burp import IMessageEditorTab           
from burp import IMessageEditorTabFactory
from burp import IProxyListener
from burp import IHttpListener
from burp import IInterceptedProxyMessage
from burp import ITab
from burp import IMessageEditorController
import json
from java.io import PrintWriter
from thread import start_new_thread
from javax.swing import JPanel,JButton,JFrame,JTextField,JLabel,BoxLayout,Box,JTable,table,JSplitPane,JPopupMenu,JMenuItem,JTabbedPane,ListSelectionModel,JToggleButton,JCheckBox,JScrollPane
from java.awt import BorderLayout,FlowLayout,GridLayout,Dimension,Component
import re





class BurpExtender(IBurpExtender,IMessageEditorTabFactory,IProxyListener,IHttpListener,ITab,IMessageEditorController):
	tableID=0
	crlf_requests=[]
	urls_log=[]
	isRunning=True
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks 
		self._requestViewer = callbacks.createMessageEditor(self, False)
		self._responseViewer = callbacks.createMessageEditor(self, False)
		self._helpers = callbacks.getHelpers()
		self._stdout = PrintWriter(callbacks.getStdout(), True)	
		callbacks.addSuiteTab(self)    #add tab
		# set our extension name.
		callbacks.setExtensionName("Hunter CRLF") 
		# callbacks.registerProxyListener(self)
		callbacks.registerHttpListener(self)
		return

	def getTabCaption(self):
		return "Hunter CRLF"

	def getHttpService(self):
		return self.crlf_requests[self.newTable.getSelectedRow()].getHttpService()

	def getRequest(self):
		return self.crlf_requests[self.newTable.getSelectedRow()].getRequest()

   	def getResponse(self):
		return self.crlf_requests[self.newTable.getSelectedRow()].getResponse()

	def rowFocusGained(self,e):
		if(self.newTable.getSelectedRow()!=-1):
			self._requestViewer.setMessage(self.crlf_requests[self.newTable.getSelectedRow()].getRequest(), True)
			self._responseViewer.setMessage(self.crlf_requests[self.newTable.getSelectedRow()].getResponse(), True)
	def SendRequestRepeater(self,e):
		self._callbacks.se
		# self._stdout.println('SendRequestRepeater'+str(self.newTable.getSelectedRow()))

	def startOrStop(self, event):
		if self.startButton.getText() == "Hunter CRLF is Off":
			self.startButton.setText("Hunter CRLF is On")
			self.startButton.setSelected(True)
			self.isRunning = True
		else:
			self.startButton.setText("Hunter CRLF is Off")
			self.startButton.setSelected(False)
			self.isRunning = False
	def reset(self,event):
		self.crlf_requests=[]
		self.tableID=0
		self.tableModel.setRowCount(0)
		self.urls_log=[]

	def clearAll(self,event):
		self.crlf_requests=[]
		self.tableID=0
		self.tableModel.setRowCount(0)
		# self._requestViewer.setMessage(None, True)
		# self._responseViewer.setMessage(None, True)
	def getUiComponent(self):
		mainPanel = JPanel()
		mainPanel.setLayout(BoxLayout(mainPanel, BoxLayout.Y_AXIS))


		#####################Popup Menu##############
		popupMenu =  JPopupMenu();
		sendToRepeaterMenu =  JMenuItem("Send to Repeater");
		sendToRepeaterMenu.addActionListener(self.SendRequestRepeater)	
		menuItemCopy =JMenuItem("Copy URL");
		menuItemClearAll =  JMenuItem("Clear All",actionPerformed=self.clearAll);
		popupMenu.add(sendToRepeaterMenu);
		popupMenu.add(menuItemCopy);
		popupMenu.add(menuItemClearAll);
		##################################TABLE PANEL#############
		tablePanel =JPanel()
		tablePanel.setLayout(BoxLayout(tablePanel, BoxLayout.Y_AXIS))
		tableHead=['ID','URL','paramater','payload']
		self.tableData = []
  		self.tableModel=table.DefaultTableModel(self.tableData,tableHead)
  		self.newTable=JTable()
  		self.newTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
  		selectionModel = self.newTable.getSelectionModel();
  		selectionModel.addListSelectionListener(self.rowFocusGained)
  		# self._stdout.println(JTable)
  		# self.newTable.addMouseListener(self.test)
  		# self.newTable.setAutoCreateRowSorter(True)  #Add row sorter
  		self.newTable.setModel(self.tableModel)
  		self.newTable.setComponentPopupMenu(popupMenu)
		scrollPane = JScrollPane(self.newTable)
  		# tablePanel.add(self.newTable.getTableHeader())
  		# tablePanel.add(self.newTable)
		tablePanel.add(scrollPane)
  		####################################Config Tab#####################
  		configPanel=JPanel()
  		# configPanel.setLayout(FlowLayout())
  		# configPanel.setLayout(None)
  		configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
		self.startButton=JToggleButton("Hunter CRLF is On",actionPerformed=self.startOrStop)
		self.startButton.setSelected(True)
		self.startButton.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.startButton.setPreferredSize(Dimension(200, 35));
		self.startButton.setMaximumSize(Dimension(200, 35));
		self.inScopeCheckBox=JCheckBox("Only In-Scope requests",selected=True);
		self.dontRepeatRequests=JCheckBox("Don't Repeat Requests",selected=True);
		self.onlyReflectedCheckBox=JCheckBox("Only Reflected Paramaters",selected=True);
		# self.checkForHunterx=JCheckBox("Search for hunterx in responses");
		self.inScopeCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.dontRepeatRequests.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.onlyReflectedCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.checkForHunterx.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payloadsLabel=JLabel("Payloads")
		# self.payload1=JCheckBox("xuicodexua\\")
		# self.payload2=JCheckBox("xuicodexub\"\"",selected=True)
		# self.payload3=JCheckBox("xuicodexuc'",selected=True)
		# self.payload4=JCheckBox("xuicodexud\\\"",selected=True)
		# self.payload5=JCheckBox("xuicodexue</script>",selected=True)
		# self.payload1.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payload2.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payload3.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payload4.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payload5.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.payloadsLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.resetButton = JButton("Reset",actionPerformed=self.reset)
		self.resetButton.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.startButton.setSize(Dimension(200, 40));
		# self.startButton.setBounds(10, 20, 230, 35)
		configPanel.add(Box.createRigidArea(Dimension(0, 25)))
		configPanel.add(self.startButton)
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  		configPanel.add(self.inScopeCheckBox)
  		configPanel.add(self.dontRepeatRequests)
  		configPanel.add(self.onlyReflectedCheckBox)
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  # 		configPanel.add(self.payloadsLabel)
		# configPanel.add(Box.createRigidArea(Dimension(0, 10)))
  # 		configPanel.add(self.payload1)
  # 		configPanel.add(self.payload2)
  # 		configPanel.add(self.payload3)
  # 		configPanel.add(self.payload4)
  # 		configPanel.add(self.payload5)
		configPanel.add(Box.createRigidArea(Dimension(0, 10)))
  		# configPanel.add(Box.createVerticalGlue())
  		configPanel.add(self.resetButton)
  		# configPanel.add(Box.createVerticalGlue())

		####################################Tabs View#######################
		tabs = JTabbedPane()
		tabs.addTab("Request", self._requestViewer.getComponent())
		tabs.addTab("Response", self._responseViewer.getComponent())
		tabs.addTab("Configuration", configPanel)
		tabs.setSelectedIndex(0) #set selected tab
		###################################SPLIT Pane############################
		splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		splitPane.setLeftComponent(tablePanel)
		splitPane.setRightComponent(tabs);
		# splitPane.setResizeWeight(1)
		splitPane.setDividerLocation(1100 ); 
		mainPanel.add(splitPane)
		# panel.add(newTable)
		return mainPanel


	def __println(self,txt):
		self._stdout.println(txt)

	def crlfChecker(self,req,request_response):
		url=req.url
		host=request_response.getHttpService().getHost();
		port=request_response.getHttpService().getPort();
		protocol=request_response.getHttpService().getProtocol() == "https"
		params=req.getParameters()
		headers=req.getHeaders()
		payloads=["%00","%0a","%0a%20","%0d","%0d%09","%0d%0a","%0d%0a%09","%0d%0a%20","%0d%20","%20","%20%0a","%20%0d","%20%0d%0a","%23%0a","%23%0a%20","%23%0d","%23%0d%0a","%23%oa","%25%30","%25%30%61","%2e%2e%2f%0d%0a","%2f%2e%2e%0d%0a","%2f..%0d%0a","%3f","%3f%0a","%3f%0d","%3f%0d%0a","%e5%98%8a%e5%98%8d","%e5%98%8a%e5%98%8d%0a","%e5%98%8a%e5%98%8d%0d","%e5%98%8a%e5%98%8d%0d%0a","%e5%98%8a%e5%98%8d%e5%98%8a%e5%98%8d","%u0000","%u000a","%u000d","\r","\r%20","\r\n","\r\n%20","\r\n\t","\r\t"]
		if(self.dontRepeatRequests.isSelected() and url in self.urls_log):
			return
		
		request=request_response.getRequest()
		response=request_response.getResponse()
		response_headers=self._callbacks.getHeaders(response)
		response_headers_joined='||'.join(response_headers)
		isTooManyRequests=False
		self._stdout.println("Testing:  "+str(url))
		for param in params:
			if(param.getType()!=param.PARAM_URL):
				continue
			paramName=param.getName()
			paramValue=param.getValue()
			paramType=param.getType()
			if((self.onlyReflectedCheckBox.isSelected== False) or (paramValue in response_headers_joined or self._helpers.urlDecode(paramValue) in self._helpers.urlDecode(response_headers_joined))):
				for payload in ["x%0d%0acrlfcodecrlf","x%0D%0Acrlfcodecrlf%3a%20x","x%E5%98%8A%E5%98%8Dcrlfcodecrlf"]:
					newReq=self._helpers.updateParameter(request,self._helpers.buildParameter(paramName,payload,paramType))
					new_request_response=self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(host),int(port),protocol),newReq)
					if(new_request_response.getStatusCode()==429):isTooManyRequests=True
					new_response_headers=self._callbacks.getHeaders(request_response.getResponse())
					for header in new_response_headers:
						if(header.lower().startswith('crlfcode')):
							self._stdout.println("CRLF AT "+str(url)+"           "+paramName+'='+payload)
							self.crlf_requests.append(new_request_response)
							self.tableID+=1
							self.tableModel.addRow([self.tableID,url,paramName,payload])
		if(url not in self.urls_log and isTooManyRequests == False): self.urls_log.append(url)


	# 	isTooManyRequests=False
	# 	if(self.dontRepeatRequests.isSelected() and url in self.urls_log):
	# 		return
	# 	self._stdout.println("Testing:  "+str(url))
	# 	for param in (params):
	# 		if(param.getType()!=param.PARAM_URL):
	# 			continue

	# 		newReq=messageInfo.getRequest()
	# 		payloads=[["xuicodexua\\",["xuicodexua\\'","xuicodexua\\\""]],["xuicodexub\"",["xuicodexub\"\"","xuicodexub\\\"\\\""]],["xuicodexuc'",["xuicodexuc''","xuicodexuc\\'\\'"]],["xuicodexud\\\"x",["xuicodexud\\\\\"x"]]]
	# 		filter_checkboxes=[self.payload1.isSelected(),self.payload2.isSelected(),self.payload3.isSelected(),self.payload4.isSelected()]
	# 		filtered_payloads=[p for (i,p) in enumerate(payloads) if filter_checkboxes[i]]
	# 		for payload in filtered_payloads:
	# 			newReq=self._helpers.updateParameter(newReq,self._helpers.buildParameter(param.getName(),payload[0],param.getType()))
	# 			request_response=self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(host),int(port),protocol),newReq)
	# 			# request_response=self._callbacks.makeHttpRequest(str(host),int(port),protocol,newReq)
	# 			# self._stdout.println(self._helpers.analyzeResponse((request_response)).getStatusCode())
	# 			response=self._helpers.bytesToString(request_response.getResponse())
	# 			if(request_response.getStatusCode()== 429): isTooManyRequests=True
	# 			if(any(reflected_payload in response for reflected_payload in payload[1])):   #check if any of reflected payload list appears in the response  
	# 					self._stdout.println("XSS AT "+str(url)+"           "+param.getName()+'='+payload[0])
	# 					self.tableID+=1
	# 					self.tableModel.addRow([self.tableID,url,param.getName(),payload[0]])
	# 					self.crlf_requests.append(request_response)
	# 		#</script> Payload
	# 		if(self.payload5.isSelected()):
	# 			newReq=self._helpers.updateParameter(newReq,self._helpers.buildParameter(param.getName(),'xuicodexui</script>',param.getType()))
	# 			request_response=self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(host),int(port),protocol),newReq)
	# 			if(request_response.getStatusCode()== 429): isTooManyRequests=True
	# 			response=self._helpers.bytesToString(request_response.getResponse())
	# 			response=response.replace('\n','').replace('\r','')   #To prevent regex Catastrophic backtracking
	# 			result=re.search(r'<script[^_]+?(?=xuicodexue</script>)[\s\S]*?<\/script>',response)
	# 			if(result):
	# 				self._stdout.println("XSS AT "+str(url)+"           "+param.getName()+'='+payload[0])
	# 				self.tableID+=1
	# 				self.tableModel.addRow([self.tableID,url,param.getName(),'xuicodexue</script>'])
	# 				self.crlf_requests.append(request_response)
	# 		if(url not in self.urls_log and isTooManyRequests == False): self.urls_log.append(url)
			

	def processHttpMessage(self, toolFlag, messageIsRequest, request_response):
		req_bytes=request_response.getRequest()
		req= self._helpers.analyzeRequest(request_response.getHttpService(),req_bytes)
		url=req.getUrl()
		params=req.getParameters()
		method=req.getMethod()
		if self.isRunning and method=='GET' and len(params) and toolFlag == self._callbacks.TOOL_PROXY and ((self._callbacks.isInScope(url) and self.inScopeCheckBox.isSelected()) or not self.inScopeCheckBox.isSelected()):
			if  messageIsRequest==False :  #message is Response
				# self._stdout.println(self.inScopeCheckBox.isSelected())
				start_new_thread(self.crlfChecker,(req,request_response))
			else:
				headers=req.getHeaders()
				new_headers=[]
				for h in headers:
					header_name=h.split(':')[0]
					if(header_name not in ['If-Modified-Since','If-None-Match']):
						new_headers.append(h)
				request_response.setRequest(self._helpers.buildHttpMessage(new_headers,None))


		# if messageIsRequest and self.isRunning:
		# 	req= self._helpers.analyzeRequest(messageInfo)
		# 	method=req.getMethod()
		# 	params=req.getParameters()
		# 	url=req.getUrl()
		# 	# self._stdout.println(self.inScopeCheckBox.isSelected())
		# 	if method=='GET' and len(params) and toolFlag == self._callbacks.TOOL_PROXY and ((self._callbacks.isInScope(url) and self.inScopeCheckBox.isSelected()) or not self.inScopeCheckBox.isSelected()):
		# 		start_new_thread(self.xssChecker,(messageInfo,))

		# elif messageIsResponse and self.searchForhunterx.isSelected():
			#EE


# def processProxyMessage(self, messageIsRequest, message):
# 		if messageIsRequest:
# 			messageInform = message.getMessageInfo()
# 			req= self._helpers.analyzeRequest(messageInform)
# 			method=req.getMethod()
# 			self._stdout.println(messageInform.getHttpService().getHost())
# 			self._stdout.println(method)
# 			return
