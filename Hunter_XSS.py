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
	xss_requests=[]
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
		callbacks.setExtensionName("Hunter XSS") 
		# callbacks.registerProxyListener(self)
		callbacks.registerHttpListener(self)
		return

	def getTabCaption(self):
		return "Hunter XSS"

	def getHttpService(self):
		return self.xss_requests[self.newTable.getSelectedRow()].getHttpService()

	def getRequest(self):
		return self.xss_requests[self.newTable.getSelectedRow()].getRequest()

   	def getResponse(self):
		return self.xss_requests[self.newTable.getSelectedRow()].getResponse()

	def rowFocusGained(self,e):
		if(self.newTable.getSelectedRow()!=-1):
			self._requestViewer.setMessage(self.xss_requests[self.newTable.getSelectedRow()].getRequest(), True)
			self._responseViewer.setMessage(self.xss_requests[self.newTable.getSelectedRow()].getResponse(), True)
	def SendRequestRepeater(self,e):
		self._callbacks.se
		# self._stdout.println('SendRequestRepeater'+str(self.newTable.getSelectedRow()))

	def startOrStop(self, event):
		if self.startButton.getText() == "Hunter XSS is Off":
			self.startButton.setText("Hunter XSS is On")
			self.startButton.setSelected(True)
			self.isRunning = True
		else:
			self.startButton.setText("Hunter XSS is Off")
			self.startButton.setSelected(False)
			self.isRunning = False
	def reset(self,event):
		self.xss_requests=[]
		self.tableID=0
		self.tableModel.setRowCount(0)
		self.urls_log=[]

	def clearAll(self,event):
		self.xss_requests=[]
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
		self.startButton=JToggleButton("Hunter XSS is On",actionPerformed=self.startOrStop)
		self.startButton.setSelected(True)
		self.startButton.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.startButton.setPreferredSize(Dimension(200, 35));
		self.startButton.setMaximumSize(Dimension(200, 35));
		self.inScopeCheckBox=JCheckBox("Only In-Scope requests",selected=True);
		self.dontRepeatRequests=JCheckBox("Don't Repeat Requests",selected=True);
		# self.checkForHunterx=JCheckBox("Search for hunterx in responses");
		self.inScopeCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.dontRepeatRequests.setAlignmentX(Component.CENTER_ALIGNMENT)
		# self.checkForHunterx.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.payloadsLabel=JLabel("Payloads")
		self.payload1=JCheckBox("xuicodexua\\")
		self.payload2=JCheckBox("xuicodexub\"\"",selected=True)
		self.payload3=JCheckBox("xuicodexuc'",selected=True)
		self.payload4=JCheckBox("xuicodexud\\\"",selected=True)
		self.payload5=JCheckBox("xuicodexue</script>",selected=True)
		self.payload1.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.payload2.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.payload3.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.payload4.setAlignmentX(Component.CENTER_ALIGNMENT)
		self.payload5.setAlignmentX(Component.CENTER_ALIGNMENT)
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
		configPanel.add(Box.createRigidArea(Dimension(0, 20)))
  		configPanel.add(self.payloadsLabel)
		configPanel.add(Box.createRigidArea(Dimension(0, 10)))
  		configPanel.add(self.payload1)
  		configPanel.add(self.payload2)
  		configPanel.add(self.payload3)
  		configPanel.add(self.payload4)
  		configPanel.add(self.payload5)
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

	def xssChecker(self,messageInfo):
		req= self._helpers.analyzeRequest(messageInfo)
		host=messageInfo.getHttpService().getHost();
		port=messageInfo.getHttpService().getPort();
		protocol=messageInfo.getHttpService().getProtocol() == "https"
		params=req.getParameters()
		headers=req.getHeaders()
		url=req.url
		isTooManyRequests=False
		if(self.dontRepeatRequests.isSelected() and url in self.urls_log):
			return
		new_headers=[]
		for h in headers:
			header_name=h.split(':')[0]
			if(header_name not in ['If-Modified-Since','If-None-Match']):
				new_headers.append(h)
		messageInfo.setRequest(self._helpers.buildHttpMessage(new_headers,None))
		self._stdout.println("Testing:  "+str(url))
		for param in (params):
			if(param.getType()!=param.PARAM_URL):
				continue

			newReq=messageInfo.getRequest()
			payloads=[["xuicodexua\\",["xuicodexua\\'","xuicodexua\\\""]],["xuicodexub\"",["xuicodexub\"\"","xuicodexub\\\"\\\""]],["xuicodexuc'",["xuicodexuc''","xuicodexuc\\'\\'"]],["xuicodexud\\\"x",["xuicodexud\\\\\"x"]]]
			filter_checkboxes=[self.payload1.isSelected(),self.payload2.isSelected(),self.payload3.isSelected(),self.payload4.isSelected()]
			filtered_payloads=[p for (i,p) in enumerate(payloads) if filter_checkboxes[i]]
			for payload in filtered_payloads:
				newReq=self._helpers.updateParameter(newReq,self._helpers.buildParameter(param.getName(),payload[0],param.getType()))
				request_response=self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(host),int(port),protocol),newReq)
				# request_response=self._callbacks.makeHttpRequest(str(host),int(port),protocol,newReq)
				# self._stdout.println(self._helpers.analyzeResponse((request_response)).getStatusCode())
				response=self._helpers.bytesToString(request_response.getResponse())
				if(request_response.getStatusCode()== 429): isTooManyRequests=True
				if(any(reflected_payload in response for reflected_payload in payload[1])):   #check if any of reflected payload list appears in the response  
						self._stdout.println("XSS AT "+str(url)+"           "+param.getName()+'='+payload[0])
						self.tableID+=1
						self.tableModel.addRow([self.tableID,url,param.getName(),payload[0]])
						self.xss_requests.append(request_response)
			#</script> Payload
			if(self.payload5.isSelected()):
				newReq=self._helpers.updateParameter(newReq,self._helpers.buildParameter(param.getName(),'xuicodexui</script>',param.getType()))
				request_response=self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(host),int(port),protocol),newReq)
				if(request_response.getStatusCode()== 429): isTooManyRequests=True
				response=self._helpers.bytesToString(request_response.getResponse())
				response=response.replace('\n','').replace('\r','')   #To prevent regex Catastrophic backtracking
				result=re.search(r'<script[^_]+?(?=xuicodexue</script>)[\s\S]*?<\/script>',response)
				if(result):
					self._stdout.println("XSS AT "+str(url)+"           "+param.getName()+'='+payload[0])
					self.tableID+=1
					self.tableModel.addRow([self.tableID,url,param.getName(),'xuicodexue</script>'])
					self.xss_requests.append(request_response)
			if(url not in self.urls_log and isTooManyRequests == False): self.urls_log.append(url)
			

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		if messageIsRequest and self.isRunning:
			req= self._helpers.analyzeRequest(messageInfo)
			method=req.getMethod()
			params=req.getParameters()
			url=req.getUrl()
			# self._stdout.println(self.inScopeCheckBox.isSelected())
			if method=='GET' and len(params) and toolFlag == self._callbacks.TOOL_PROXY and ((self._callbacks.isInScope(url) and self.inScopeCheckBox.isSelected()) or not self.inScopeCheckBox.isSelected()):
				start_new_thread(self.xssChecker,(messageInfo,))

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
