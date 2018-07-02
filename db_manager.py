import npyscreen
import sys
import time
import _thread # Works like the threading module

class ReprisalDatabase(npyscreen.ActionForm):

	def on_ok(self):

		self.parentApp.switchForm('MAIN')

'''class DisplayAddresses(npyscreen.ActionForm):

	def create(self):

		self.myName = self.add(npyscreen.TitleText, name='Name')

	def on_ok(self):

		sys.exit(0)'''

class WidgetClassOveride(npyscreen.MultiLineAction):

	def actionHighlighted(self, act_on_this, keypress):

		self.parent.parentApp.getForm('RDAT')
		self.parent.parentApp.switchForm('RDAT')


class DisplayAddresses(npyscreen.FormMutt):

	# So in a FormMutt class the beforeEditing method is called first
	# I assume that FormMutt is an easier way to create a form...should read more

	MAIN_WIDGET_CLASS = WidgetClassOveride

	'''def __init__(self, *args, **keywords):

		super(DisplayAddresses, self).__init__(*args, **keywords)
		timed_thread = _thread.start_new_thread(self.update_addresses, ('',))'''

	def beforeEditing(self):

		self.update_addresses()

	def update_addresses(self):

		self.wMain.display()

class DB_Manager(npyscreen.NPSAppManaged):

	def onStart(self):

		self.addForm('MAIN', DisplayAddresses)
		self.addForm('RDAT', ReprisalDatabase)
		#timed_thread = _thread.start_new_thread()

	'''def doSomething(self):

		while True:

			sleep(4)'''

app = DB_Manager()
app.run()