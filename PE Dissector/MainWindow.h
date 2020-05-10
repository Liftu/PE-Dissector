#pragma once

#include <QtWidgets/QMainWindow>
#include <QtWidgets/qlabel.h>

#include "ui_MainWindow.h"
#include "PE Dissector.h"

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget *parent = Q_NULLPTR);

private:
	Ui::MainWindowClass ui;
	QLabel* statusBarLabel;
};
