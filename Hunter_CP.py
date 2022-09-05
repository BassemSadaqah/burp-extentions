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
from javax.swing import JPanel,JButton,JFrame,JTextField,JLabel,BoxLayout,Box,JTable,table,JSplitPane,JPopupMenu,JMenuItem,JTabbedPane,ListSelectionModel,JToggleButton,JCheckBox,JScrollPane, JSlider
from java.awt import BorderLayout,FlowLayout,GridLayout,Dimension,Component
import re
import random
from java.lang import Math




class BurpExtender(IBurpExtender,IMessageEditorTabFactory,IProxyListener,IHttpListener,ITab,IMessageEditorController):
	logTableID=0
	cacherTableID=0
	log_requests=[]
	cacher_requests=[]
	urls_log=[]
	isRunning=True
	payload_headers=[['\\','huicodehui'],['X-Forwarded-Scheme','huicodehui'],['X-Forwarded-Host','huicodehui'],['X-Forwarded-For','huicodehui.com'],['X-Forwarded-Proto','123'],['X-HTTP-Method-Override','POST'],['x-amz-website-redirect-location','huicodehui'],['Authorization: huicodehui\nx: huicodehui\nAuthorization','huicodehui'],
		['X-Rewrite-Url','huicodehui'],['Authorization','huicodehui'],['X-Host','huicodehui'],['User-Agent','huicodehui'],['handle','huicodehui'],['X-Original-Url','huicodehui'],['X-Original-Host','huicodehui'],['X-Forwarded-Prefix','huicodehui'],['x-amz-server-side-encryption','huicodehui'],['Trailer','huicodehui'],['Fastly-SSL','huicodehui'],['Fastly-Host','huicodehui'],
		['Fastly-FF','huicodehui'],['Fastly-Client-IP','huicodehui'],['Content-Type','huicodehui'],['api-version','huicodehui'],['acunetix-header','huicodehui'],['Accept-Version','huicodehui'],['Accept-Encoding','huicodehui'],['Referer','huicodehui'],['X-Forwarded-Port','123'],['Null-Byte',b"\x00".decode("utf-8")],['Location','/huicodehui'],['TooLong','x'*5000]]

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks 
		self._requestViewer = callbacks.createMessageEditor(self, False)
		self._responseViewer = callbacks.createMessageEditor(self, False)
		self._originalRequestViewer = callbacks.createMessageEditor(self, False)
		self._originalResponseViewer = callbacks.createMessageEditor(self, False)
		self._helpers = callbacks.getHelpers()
		self._stdout = PrintWriter(callbacks.getStdout(), True)	
		callbacks.addSuiteTab(self)    #add tab
		# set our extension name.
		callbacks.setExtensionName("Hunter CP") 
		# callbacks.registerProxyListener(self)
		callbacks.registerHttpListener(self)
		return

	def getTabCaption(self):
		return "Hunter CP"

	def getHttpService(self):
		if(self.leftTabbledPanel.getSelectedIndex()==0):
			return self.log_requests[self.logTable.getSelectedRow()][0].getHttpService()
		elif(self.leftTabbledPanel.getSelectedIndex()==1):
			return self.cacher_requests[self.cacherTable.getSelectedRow()][0].getHttpService()



	def getRequest(self):
		self._stdout.println(self.leftTabbledPanel.getSelectedIndex())
		if(self.leftTabbledPanel.getSelectedIndex()==0):
			if(self.rightTabbedPanel.getSelectedIndex()==0):
				return self.log_requests[self.logTable.getSelectedRow()][0].getRequest()
			else:
				return self.log_requests[self.logTable.getSelectedRow()][1].getRequest()
		elif(self.leftTabbledPanel.getSelectedIndex()==1):
			if(self.rightTabbedPanel.getSelectedIndex()==0):
				return self.cacher_requests[self.cacherTable.getSelectedRow()][0].getRequest()
			else:
				return self.cacher_requests[self.cacherTable.getSelectedRow()][1].getRequest()

   	def getResponse(self):
		if(self.leftTabbledPanel.getSelectedIndex()==0):
			if(self.rightTabbedPanel.getSelectedIndex()==1):
				return self.log_requests[self.logTable.getSelectedRow()][0].getResponse()
			else:
				return self.log_requests[self.logTable.getSelectedRow()][1].getResponse()
		elif(self.leftTabbledPanel.getSelectedIndex()==1):
			if(self.rightTabbedPanel.getSelectedIndex()==1):
				return self.cacher_requests[self.cacherTable.getSelectedRow()][0].getResponse()
			else:
				return self.cacher_requests[self.cacherTable.getSelectedRow()][1].getResponse()

	def logRowFocusGained(self,event):
		if(self.logTable.getSelectedRow()!=-1):
			self._requestViewer.setMessage(self.log_requests[self.logTable.getSelectedRow()][0].getRequest(), True)
			self._responseViewer.setMessage(self.log_requests[self.logTable.getSelectedRow()][0].getResponse(), True)
			self._originalRequestViewer.setMessage(self.log_requests[self.logTable.getSelectedRow()][1].getRequest(), True)
			self._originalResponseViewer.setMessage(self.log_requests[self.logTable.getSelectedRow()][1].getResponse(), True)
	
	def cacherRowFocusGained(self,event):
		self._stdout.println('cacherRowFocusGained')
		if(self.cacherTable.getSelectedRow()!=-1):
			self._stdout.println('xxxxxxx')
			self._requestViewer.setMessage(self.cacher_requests[self.cacherTable.getSelectedRow()][0].getRequest(), True)
			self._responseViewer.setMessage(self.cacher_requests[self.cacherTable.getSelectedRow()][0].getResponse(), True)
			self._originalRequestViewer.setMessage(self.cacher_requests[self.cacherTable.getSelectedRow()][1].getRequest(), True)
			self._originalResponseViewer.setMessage(self.cacher_requests[self.cacherTable.getSelectedRow()][1].getResponse(), True)

	def startOrStop(self, event):
		if self.startButton.getText() == "Hunter CP is Off":
			self.startButton.setText("Hunter CP is On")
			self.startButton.setSelected(True)
			self.isRunning = True
		else:
			self.startButton.setText("Hunter CP is Off")
			self.startButton.setSelected(False)
			self.isRunning = False
	def reset(self,event):
		self.log_requests=[]
		self.logTableID=0
		self.tableModel.setRowCount(0)
		self.urls_log=[]
		self.cacher_requests=[]
		self.cacherTableID=0
		self.cacherModel.setRowCount(0)

	def clearAll(self,event):
		self.log_requests=[]
		self.cacher_requests=[]
		self.logTableID=0
		self.tableModel.setRowCount(0)
		self.cacherTableID=0
		self.cacherModel.setRowCount(0)

		# self._requestViewer.setMessage(None, True)
		# self._responseViewer.setMessage(None, True)
	def sendToCacher(self,rowID):   #rowID will be passed as an event object if called from right click menu
		if(isinstance(rowID, int)):
			selectedRow=rowID
		else:
			selectedRow = self.logTable.getSelectedRow()
		if(selectedRow > -1):
			selectedCpRequestResponse = self.log_requests[selectedRow][0]
			selectedOriginalRequestResponse = self.log_requests[selectedRow][1]
			reasonId=self.log_requests[selectedRow][4]
			start_new_thread(self.tryToCache,(selectedRow,selectedCpRequestResponse,selectedOriginalRequestResponse,reasonId))  #last comma to convert to tuple

	def tryToCache(self,logSelectedRow,cpRequestResponse,originalRequestResponse,reasonId):
		cpReqs=[]
		cache_buster=str(random.randint(1, 1000000))
		cpRequest=cpRequestResponse.getRequest()
		cpRequest=self._helpers.updateParameter(cpRequest,self._helpers.buildParameter('xcachebuster',cache_buster,0))
		for i in range(self.cacherSlider.getValue()): cpReqs.append(self._callbacks.makeHttpRequest(cpRequestResponse.getHttpService(),cpRequest))
		originalRequest=originalRequestResponse.getRequest()
		originalRequest=self._helpers.updateParameter(originalRequest,self._helpers.buildParameter('xcachebuster',cache_buster,0))
		originalResponse=self._callbacks.makeHttpRequest(originalRequestResponse.getHttpService(),originalRequest)
		originalResponseStatusCode=originalResponse.getStatusCode()
		originalResponseText = self._helpers.bytesToString(originalResponse.getResponse())
		isCached=False
		isHit=False
		if(reasonId == 0):
			for req in cpReqs:
				if(req.getStatusCode() == originalResponse.getStatusCode()):
					isCached=True
					self.addCacherRow(logSelectedRow,req,originalResponse,'True')
					break
		elif(reasonId == 1 and 'huicodehui' in originalResponseText):
			isCached=True
			self.addCacherRow(logSelectedRow,cpReqs[-1],originalResponse,'True')
		elif(reasonId == 2 ):
			for req in cpReqs:
				cpResText=self._helpers.bytesToString(req.getResponse())
				responseSimilarity=(float(len(cpResText))/float(len(originalResponseText)))*100
				if(responseSimilarity > 90):
					isCached=True
					self.addCacherRow(logSelectedRow,req,originalResponse,'True')
					break

		if(isCached==False):
			for req in cpReqs:
				headers=self._callbacks.getHeaders(req.getResponse())
				for header in headers:
					if('HIT' in header):
						isHit=True
						self.addCacherRow(logSelectedRow,req,originalResponse,'Maybe')
						break
				if isHit: break
		if(isHit==False and isCached==False): self.addCacherRow(logSelectedRow,cpReqs[-1],originalResponse,'False')
			


	def addCacherRow(self,logSelectedRow,cpRequestResponse,originalRequestResponse,cached):
		self.cacherTableID+=1
		url=self.log_requests[logSelectedRow][2]
		payload=self.log_requests[logSelectedRow][3]
		reason=self.log_requests[logSelectedRow][5]
		self.cacherModel.addRow([self.cacherTableID,url,cpRequestResponse.getStatusCode(),originalRequestResponse.getStatusCode(),payload,reason,cached])
		self.cacher_requests.append([cpRequestResponse,originalRequestResponse,logSelectedRow])
	def getUiComponent(self):
		mainPanel = JPanel()
		mainPanel.setLayout(BoxLayout(mainPanel, BoxLayout.Y_AXIS))


		#####################Popup Menu##############
		popupMenu =  JPopupMenu();
		sendToRepeaterMenu =  JMenuItem("Send to Cacher",actionPerformed=self.sendToCacher);
		# sendToRepeaterMenu.addActionListener(self.SendRequestRepeater)	
		menuItemCopy =JMenuItem("Copy URL");
		menuItemClearAll =  JMenuItem("Clear All",actionPerformed=self.clearAll);
		popupMenu.add(sendToRepeaterMenu);
		popupMenu.add(menuItemCopy);
		popupMenu.add(menuItemClearAll);
		##################################TABLE PANEL#############
		tablePanel =JPanel()
		tablePanel.setLayout(BoxLayout(tablePanel, BoxLayout.Y_AXIS))
		tableHead=['ID','URL','Original Status Code','New Status Code','Payload','Reason','Flags']
		self.logTableData = []
  		self.tableModel=table.DefaultTableModel(self.logTableData,tableHead)
  		self.logTable=JTable()
  		self.logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
  		selectionModel = self.logTable.getSelectionModel();
  		selectionModel.addListSelectionListener(self.logRowFocusGained)
  		# self._stdout.println(JTable)
  		# self.logTable.addMouseListener(self.test)
  		# self.logTable.setAutoCreateRowSorter(True)  #Add row sorter
  		self.logTable.setComponentPopupMenu(popupMenu)
		self.logTable.setModel(self.tableModel)
		tableWidth= self.logTable.getPreferredSize().width
		self.logTable.getColumn("ID").setPreferredWidth(Math.round(tableWidth / 110 * 5))
		self.logTable.getColumn("URL").setPreferredWidth(Math.round(tableWidth / 110 * 50))
		self.logTable.getColumn("Original Status Code").setPreferredWidth(Math.round(tableWidth / 110 * 10))
		self.logTable.getColumn("New Status Code").setPreferredWidth(Math.round(tableWidth / 110 * 10))
		self.logTable.getColumn("Payload").setPreferredWidth(Math.round(tableWidth / 110 * 15))
		self.logTable.getColumn("Reason").setPreferredWidth(Math.round(tableWidth / 110 * 10))
		self.logTable.getColumn("Flags").setPreferredWidth(Math.round(tableWidth / 110 * 10))
		scrollPane = JScrollPane(self.logTable)
  		# tablePanel.add(self.logTable.getTableHeader())
  		# tablePanel.add(self.logTable)
		tablePanel.add(scrollPane)
		#################################Cacher table#############
		cacherPanel =JPanel()
		cacherPanel.setLayout(BoxLayout(cacherPanel, BoxLayout.Y_AXIS))
		cacherTableHead=['ID','URL','Original Status Code','New Status Code','Payload','Reason','Cached']
		self.cacherData = []
  		self.cacherModel=table.DefaultTableModel(self.cacherData,cacherTableHead)
  		self.cacherTable=JTable()
  		self.cacherTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
  		cacherSelectionModel = self.cacherTable.getSelectionModel();
  		cacherSelectionModel.addListSelectionListener(self.cacherRowFocusGained)
		self.cacherTable.setModel(self.cacherModel)
		cacherTableWidth= self.cacherTable.getPreferredSize().width
		self.cacherTable.getColumn("ID").setPreferredWidth(Math.round(cacherTableWidth / 110 * 5))
		self.cacherTable.getColumn("URL").setPreferredWidth(Math.round(cacherTableWidth / 110 * 50))
		self.cacherTable.getColumn("Original Status Code").setPreferredWidth(Math.round(cacherTableWidth / 110 * 10))
		self.cacherTable.getColumn("New Status Code").setPreferredWidth(Math.round(cacherTableWidth / 110 * 10))
		self.cacherTable.getColumn("Payload").setPreferredWidth(Math.round(cacherTableWidth / 110 * 15))
		self.cacherTable.getColumn("Reason").setPreferredWidth(Math.round(cacherTableWidth / 110 * 10))
		self.cacherTable.getColumn("Cached").setPreferredWidth(Math.round(cacherTableWidth / 110 * 10))
		cacherScrollPane = JScrollPane(self.cacherTable)
		cacherPanel.add(cacherScrollPane)
		#################################LEFT PANEL###############
		self.leftTabbledPanel = JTabbedPane()
		self.leftTabbledPanel.addTab("   Log   ", tablePanel)
		self.leftTabbledPanel.addTab("   Cacher   ", cacherPanel)
		self.leftTabbledPanel.setSelectedIndex(0) #set selected tab
  		####################################Config Tab#####################
  		configPanel=JPanel()
  		# configPanel.setLayout(FlowLayout())
  		# configPanel.setLayout(None)
  		configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
		self.startButton=JToggleButton("Hunter CP is On",actionPerformed=self.startOrStop)
		self.startButton.setSelected(True)
		self.startButton.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.startButton.setPreferredSize(Dimension(200, 35));
		self.startButton.setMaximumSize(Dimension(200, 35));
		self.inScopeCheckBox=JCheckBox("Only In-Scope requests",selected=True);
		self.dontRepeatRequests=JCheckBox("Don't Repeat Requests",selected=True);
		self.autoSendToCacherIfAkamai=JCheckBox("Auto test Akamai & awslb",selected=False);
		self.autoSendToCacher=JCheckBox("Auto send to cacher",selected=False);
		self.compareSize=JCheckBox("Compare Size",selected=True);
		self.fastMode=JCheckBox("Fast Mode");
		# self.checkForHunterx=JCheckBox("Search for hunterx in responses");
		self.inScopeCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.autoSendToCacherIfAkamai.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.autoSendToCacher.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.dontRepeatRequests.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.fastMode.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.compareSize.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.checkForHunterx.setAlignmentX(Component.CENTER_ALIGNMENT)
		cacherSliderLabel=JLabel("Cacher Threads (5-20)")
		cacherSliderLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.cacherSlider = JSlider(5,20,5)
		self.cacherSlider.setMaximumSize(Dimension(200, 35));
		self.payloadsLabel=JLabel("Payloads")
		payloads_box = JPanel()
		payloadScrollPane = JScrollPane(payloads_box)
		payloadScrollPane.setMaximumSize(Dimension(400, 35));
		payloadScrollPane.setAlignmentX(Component.CENTER_ALIGNMENT)
		payloads_box.setLayout(BoxLayout(payloads_box, BoxLayout.Y_AXIS))
		payloads_box.setAlignmentX(Component.CENTER_ALIGNMENT)
		for payload in self.payload_headers:
			newCheckBox=JCheckBox(payload[0],selected=True)
			if(payload[0]=='TooLong'): newCheckBox.setSelected(False)
			payload.append(newCheckBox)
		self.payloadsLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.resetButton = JButton("Reset",actionPerformed=self.reset)
		self.resetButton.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.startButton.setSize(Dimension(200, 40));
		# self.startButton.setBounds(10, 20, 230, 35)
		configPanel.add(Box.createRigidArea(Dimension(0, 25)))
		configPanel.add(self.startButton)
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  		configPanel.add(self.inScopeCheckBox)
  		configPanel.add(self.dontRepeatRequests)
  		configPanel.add(self.compareSize)
  		configPanel.add(self.autoSendToCacherIfAkamai)
  		configPanel.add(self.autoSendToCacher)
  		configPanel.add(self.fastMode)
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  		configPanel.add(cacherSliderLabel)
  		configPanel.add(self.cacherSlider)
		configPanel.add(Box.createRigidArea(Dimension(0, 5)))
  		configPanel.add(self.payloadsLabel)
		configPanel.add(Box.createRigidArea(Dimension(0, 5)))
		for payload in self.payload_headers: payloads_box.add(payload[2])
		configPanel.add(payloadScrollPane)
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  		# configPanel.add(Box.createVerticalGlue())
  		configPanel.add(self.resetButton)
  		# configPanel.add(Box.createVerticalGlue())

		####################################Tabs View#######################
		self.rightTabbedPanel = JTabbedPane()
		self.rightTabbedPanel.addTab("Request", self._requestViewer.getComponent())
		self.rightTabbedPanel.addTab("Response", self._responseViewer.getComponent())
		self.rightTabbedPanel.addTab("Original Request", self._originalRequestViewer.getComponent())
		self.rightTabbedPanel.addTab("Original Response", self._originalResponseViewer.getComponent())
		self.rightTabbedPanel.addTab("Configuration", configPanel)
		self.rightTabbedPanel.setSelectedIndex(0) #set selected tab
		###################################SPLIT Pane############################
		splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		splitPane.setLeftComponent(self.leftTabbledPanel)
		splitPane.setRightComponent(self.rightTabbedPanel);
		# splitPane.setResizeWeight(1)
		splitPane.setDividerLocation(1100); 
		mainPanel.add(splitPane)
		# panel.add(logTable)
		return mainPanel


	def __println(self,txt):
		self._stdout.println(txt)

	def cpChecker(self,req,request_response):
		#ToDo ---> Capatalized HOST  + Referer header
		url=req.url
		originalStatusCode=request_response.getStatusCode()
		originalResponse=self._helpers.bytesToString(request_response.getResponse())
		if(self.dontRepeatRequests.isSelected() and url in self.urls_log):
			return
		if(url not in self.urls_log): self.urls_log.append(url)
		self._stdout.println("Testing:  "+str(url))

		filtered_headers=[p for p in self.payload_headers if p[2].isSelected()]
		filtered_headers.append(['Host',request_response.getHttpService().getHost().upper()])
		# filtered_headers.append(['Null-Byte',self._helpers.bytesToString([00])])
		req_headers=req.getHeaders()

		cpData=self.makeReqWithPayloads(request_response,req_headers,filtered_headers)
		if cpData:
			if self.fastMode.isSelected():
				self.addRow(request_response,cpData[1],url,str(originalStatusCode),str(cpData[1].getStatusCode()),'ALL',cpData[0])
			else:
				cpFound = self.recursionMode(request_response,req_headers,filtered_headers)
				if cpFound==False:
					self.addRow(request_response,cpData[1],url,str(originalStatusCode),str(cpData[1].getStatusCode()),'ALL',cpData[0])



	def addRow(self,originalRequest,modifiedRequest,url,originalStatusCode,newStatusCode,payload,reason):
		response_headers=self._callbacks.getHeaders(modifiedRequest.getResponse())
		flag = ''
		headers_all='|||'.join(response_headers)
		if(re.search(r'Cache-Control.*no-store',headers_all,re.IGNORECASE)):
			flag='no-store'
		elif(re.search(r'Cache-Control.*private',headers_all,re.IGNORECASE)):
			flag='private'
		elif(re.search(r'Akamai',headers_all,re.IGNORECASE)):
			flag='Akamai'
		elif(re.search(r'Cache-Control.*public',headers_all,re.IGNORECASE)):
			flag='public'
		elif(re.search(r'awselb',headers_all,re.IGNORECASE)):
			flag='awselb'
		elif(re.search(r'Cache-Control.*no-cache',headers_all,re.IGNORECASE)):
			flag='no-cache'
		elif(re.search(r'Pragma.*no-cache',headers_all,re.IGNORECASE)):
			flag='Pragma: no-cache'
		# elif(re.search(r'Cache-Control: max-age=0',headers_all,re.IGNORECASE)):
		# 	flag='max-age=0'
		elif(re.search(r'Cache-Control: public',headers_all,re.IGNORECASE)):
			flag='public'

		self.logTableID+=1
		self.tableModel.addRow([self.logTableID,url,str(originalStatusCode),str(newStatusCode),payload,reason[1],flag])
		self.log_requests.append([modifiedRequest,originalRequest,url,payload,reason[0],reason[1]])
		if(self.autoSendToCacher.isSelected()):
			self.sendToCacher(len(self.log_requests)-1)
		elif(flag=='Akamai' and self.autoSendToCacherIfAkamai.isSelected()): 		#Auto Send requests to cacher if Akamai or Awselb flag exists in response
			self.sendToCacher(len(self.log_requests)-1)

	def makeReqWithPayloads(self,request_response,req_headers,payload_headers):
		filtered_req_headers=[]
		payload_headers_names=[p[0] for p in payload_headers]
		filtered_header_parsed=[(h[0]+': '+h[1]) for h in payload_headers]
		for h in req_headers:
			header_name=h.split(':')[0]
			if(header_name not in payload_headers_names+['If-Modified-Since','If-None-Match']):
				filtered_req_headers.append(h)

		newReq=self._helpers.buildHttpMessage(filtered_req_headers+filtered_header_parsed,None)
		newReq=self._helpers.addParameter(newReq,self._helpers.buildParameter('xcachebuster',str(random.randint(1, 1000000)),0))   # PARAM_URL=0
		new_request_response=self._callbacks.makeHttpRequest(request_response.getHttpService(),newReq)
		newResponse=self._helpers.bytesToString(new_request_response.getResponse())
		newStatusCode=new_request_response.getStatusCode()
		originalResponse=self._helpers.bytesToString(request_response.getResponse())
		originalStatusCode=request_response.getStatusCode()
		responseSimilarity=(float(len(newResponse))/float(len(originalResponse)))*100
		if (originalStatusCode != newStatusCode or 'huicodehui' in newResponse or (responseSimilarity < 80 and self.compareSize.isSelected())) and newStatusCode !=429:
			return [[0,'Status Code'] if originalStatusCode != newStatusCode else [1,'Reflected'] if 'huicodehui' in newResponse else [2,('Size '+str(int(responseSimilarity))+'%')],new_request_response]
		else: return False

	def recursionMode(self,request_response,req_headers,headers):
		headers_1=headers[:len(headers)//2]
		headers_2=headers[len(headers)//2:]
		return_val=False
		if(len(headers_1) > 0):
			cpData = self.makeReqWithPayloads(request_response,req_headers,headers_1)
			if cpData:
				if len(headers_1)==1:
					self.addRow(request_response,cpData[1],request_response.getUrl(),str(request_response.getStatusCode()),str(cpData[1].getStatusCode()),headers_1[0][0],cpData[0])
					return_val=True
				else: 
					if self.recursionMode(request_response,req_headers,headers_1): return_val=True

		if(len(headers_2) > 0):
			cpData = self.makeReqWithPayloads(request_response,req_headers,headers_2)
			if cpData:
				if len(headers_2)==1:
					self.addRow(request_response,cpData[1],request_response.getUrl(),str(request_response.getStatusCode()),str(cpData[1].getStatusCode()),headers_2[0][0],cpData[0])
					return_val=True
				else: 
					if self.recursionMode(request_response,req_headers,headers_2): return_val=True
		return return_val

		



	def processHttpMessage(self, toolFlag, messageIsRequest, request_response):
		req_bytes=request_response.getRequest()
		req= self._helpers.analyzeRequest(request_response.getHttpService(),req_bytes)
		url=req.getUrl()	
		method=req.getMethod()
		if self.isRunning and method=='GET' and toolFlag == self._callbacks.TOOL_PROXY and ((self._callbacks.isInScope(url) and self.inScopeCheckBox.isSelected()) or not self.inScopeCheckBox.isSelected()):
			if  messageIsRequest==False :
				# self._stdout.println(self.inScopeCheckBox.isSelected())
				start_new_thread(self.cpChecker,(req,request_response))
			else:
				headers=req.getHeaders()
				new_headers=[]
				for h in headers:
					header_name=h.split(':')[0]
					if(header_name not in ['If-Modified-Since','If-None-Match','Cache-Control','Pragma']):
						new_headers.append(h)
				request_response.setRequest(self._helpers.buildHttpMessage(new_headers,None))
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
