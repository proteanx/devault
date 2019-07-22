//
// Created by Kolby on 6/19/2019.
//


#include <startoptions.h>
#include <ui_startoptions.h>

#include <dvtui.h>

#include <QKeyEvent>
#include <QMessageBox>
#include <QPushButton>

StartOptions::StartOptions(QWidget *parent)
        : QWidget(parent), ui(new Ui::StartOptions)
        {
    ui->setupUi(this);
    if(DVTUI::customThemeIsSet()) {
        QString appstyle = "fusion";
        QApplication::setStyle(appstyle);
        setStyleSheet(DVTUI::styleSheetString);
    } 

    ui->welcomeLabel2->setText(
        tr("The 12 or 24 word recovery phrase is the master key generated by your wallet. "
           "All of your private keys in DeVault are generated from and tied to the 12 or 24 word recovery phrase."
           " 12-Word phrases may be easier to remember or write down. However, 24-Word phrases are "
           "more secure than the standard 12-word seeds. Please choose below."));
    ui->welcomeLabel3->setText(
        tr("Remember that the DeVault team has <b>no way to restore lost passwords or seeds!</b> "
           "It's very important that you store these safely yourself."
           " Note: Your passphrase can always unlock uncorrupted wallet files, but in the event of corruption only a seed phrase can restore the wallet. "
           "Your Seed will always be able to restore the wallet from scratch (without the passphrase or wallet file)."));


}

int StartOptions::getRows(){
    rows = 2;
    if (ui->Words12->isChecked()) {
        return 2;
    } else if (ui->Words24->isChecked()) {
        return 4;
    }
    return rows;
};

StartOptions::~StartOptions() {
    delete ui;
}
