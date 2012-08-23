"""
    Flaskr
    ~~~~~~

    A microblog example application written as Flask tutorial with
    Flask and sqlite3.

    Adapted for Amazon AWS Elastic Beanstalk
    by Gavin Baker <gavinb@antonym.org>

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import os
import logging

import boto
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash

# configuration
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_KEY = os.environ['AWS_SECRET_KEY']

# create our little application :)
application = app = Flask(__name__)
app.config.from_object(__name__)

def connect_db():
	logging.info('Connecting with AWS_ACCESS_KEY_ID=%s' % AWS_ACCESS_KEY_ID)
	return boto.connect_dynamodb(
		aws_access_key_id=AWS_ACCESS_KEY_ID,
		aws_secret_access_key=AWS_SECRET_KEY)

def init_db():
	conn = connect_db()
	message_table_schema = conn.create_schema(
		hash_key_name='title',
		hash_key_proto_value='S',
	)
	table = conn.create_table(
		name='entries',
		schema=message_table_schema,
		read_units=10,
		write_units=10
	)

@app.before_request
def before_request():
	g.dyndb = connect_db()
	logging.info('before_request: dyndb=%s' % g.dyndb)

@app.teardown_request
def teardown_request(exception):
	g.dyndb = None

@app.route('/')
def show_entries():
	table = g.dyndb.get_table('entries')
	entries = table.scan()
	logging.info('show_entries: N=%s' % entries)
	return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
	if not session.get('logged_in'):
		abort(401)
	table = g.dyndb.get_table('entries')
	item_data = {
		'text': request.form['text'],
	}
	item = table.new_item(
		# Our hash key is 'forum'
		hash_key=request.form['title'],
		# This has the attributes dict
		attrs=item_data
	)
	item.put()
	flash('New entry was successfully posted')
	return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST':
		if request.form['username'] != app.config['USERNAME']:
			error = 'Invalid username'
		elif request.form['password'] != app.config['PASSWORD']:
			error = 'Invalid password'
		else:
			session['logged_in'] = True
			flash('You were logged in')
			return redirect(url_for('show_entries'))
	return render_template('login.html', error=error)

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('You were logged out')
	return redirect(url_for('show_entries'))

if __name__ == '__main__':
	app.run(debug=True)
