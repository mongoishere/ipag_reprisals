import npyscreen
import ipag_reprisal
import subprocess as sp
import time
# Import IPAG Database class too

class ListView(npyscreen.MultiLineAction):

    def __init__(self, *args, **keywords):
        
        super(ListView, self).__init__(*args, **keywords)
        self.ipag = intercept_xbox_packets.SniffedDatabase()

        self.add_handlers({
            "^A": self.on_add_record,
            "^D": self.on_delete_record
        })

    def display_value(self, values):

    	return "%s ------ %s, %s -------- GT: %s" % (values[1], values[3], values[2], values[5])

    def actionHighlighted(self, act, keypress):

    	self.parent.parentApp.getForm('EDITRECORD').value = act[0]
    	self.parent.parentApp.switchForm('EDITRECORD')


    def on_add_record(self, *args, **keywords):

    	self.parent.parentApp.getForm('EDITRECORD').value = ''
    	self.parent.parentApp.switchForm('EDITRECORD')

    def on_delete_record(self, *args, **keywords):

    	self.ipag.delete_record(self.values[self.cursor_line][0])
    	self.parent.update_list()


class EditRecord(npyscreen.ActionForm):

	def create(self):

		self.value = None
		self.ipag = intercept_xbox_packets.SniffedDatabase()
		self.rowIP = self.add(npyscreen.TitleText, name = 'IP Address')
		self.rowState = self.add(npyscreen.TitleText, name = 'State')
		self.rowCity = self.add(npyscreen.TitleText, name = 'City')
		self.rowISP = self.add(npyscreen.TitleText, name = 'ISP')
		self.rowGamertag = self.add(npyscreen.TitleText, name = 'Gamertag')
		self.rowDate = self.add(npyscreen.TitleText, name = 'Date Captured')

	def beforeEditing(self):

		if self.value:

			record = self.ipag.fetch_row_from_id(self.value)
			self.name = 'Record: %s' % (record[0])
			self.rowID = record[0]
			self.rowIP.value = record[1]
			self.rowState.value = record[2]
			self.rowCity.value = record[3]
			self.rowISP.value = record[4]
			self.rowGamertag.value = record[5]
			self.rowDate.value = record[6]

		else:

			self.name = 'New Record'
			self.rowID = ''
			self.rowIP.value = ''
			self.rowState.value = ''
			self.rowCity.value = ''
			self.rowISP.value = ''
			self.rowGamertag.value = ''
			self.rowDate.value = ''

	def on_ok(self):

		if self.rowID:

			self.ipag.update_record(self.rowID,
								addr=self.rowIP.value,
								state=self.rowState.value,
								city=self.rowCity.value,
								isp=self.rowISP.value,
								gtag=self.rowGamertag.value,
								dcap=self.rowDate.value)

		else:

			self.ipag.add_sniffed(
								addr=self.rowIP.value,
								state=self.rowState.value,
								city=self.rowCity.value,
								isp=self.rowISP.value,
								gtag=self.rowGamertag.value,
								dcap=self.rowDate.value)

		self.parentApp.switchFormPrevious()

	def on_cancel(self):

		self.parentApp.switchFormPrevious()


class DatabaseDisplayForm(npyscreen.FormMutt):

	MAIN_WIDGET_CLASS = ListView

	def beforeEditing(self):

		self.ipag = intercept_xbox_packets.SniffedDatabase()
		self.update_list()

	def update_list(self):

		self.wMain.values = self.ipag.list_all_records()
		self.wMain.display()
		#self.ipag.list_all_records()

class IP_INFO(npyscreen.NPSAppManaged):

	def onStart(self):

		ipag = intercept_xbox_packets.SniffedDatabase()
		self.myDatabase = ipag
		self.addForm("MAIN", DatabaseDisplayForm)
		self.addForm("EDITRECORD", EditRecord)


def executeDBView(*args):

	try:

		App = IP_INFO()
		App.run(fork=False)

	except KeyboardInterrupt:

		App.setNextForm(None)
		App.editing = False
