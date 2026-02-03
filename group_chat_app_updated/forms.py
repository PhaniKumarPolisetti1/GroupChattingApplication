from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(3,50)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(6,128)])
    password2 = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class AdminRegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(3,50)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    admin_code = StringField('Admin Creation Code', validators=[InputRequired(), Length(4,128)])
    password = PasswordField('Password', validators=[InputRequired(), Length(6,128)])
    password2 = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Create Admin')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(6,128)])
    password2 = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(3,50)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    role = SelectField('Role', choices=[('user','User'),('admin','Admin')])
    password = PasswordField('Password', validators=[InputRequired(), Length(6,128)])
    submit = SubmitField('Add User')
