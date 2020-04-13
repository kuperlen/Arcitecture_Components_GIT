#!/usr/bin/perl
#use strict;
use warnings FATAL => 'all';
use lib qw(..);

use JSON qw( );
use JSON::MaybeXS ();

sub retrieve_and_set_secrets{
    my ($sec_name, $sec_orig_loc) = @_;
    print "Env_Name ".$env_name."; App_id ".$app_id."; Token ".$token."; secret-name ". $sec_name."; secret-value ".$sec_orig_loc."\n";
}

my $dpe_tokens = 'DPE-Tokens';
my $tokens_text = do {
    open(my $json_fh, "<:encoding(UTF-8)", $dpe_tokens)
        or die("Can't open \$dep_tokens\": $!\n");
    local $/;
    <$json_fh>
};

my $json = JSON->new;
my $data = $json->decode($tokens_text);

local $token = $data->{DPE_TOKEN};
local$app_id = $data->{DPE_APPID};
local $env_name = $data->{APP_ENV_NAME};

my $secrets = $data->{secrets};

#while ( my ($k,$v) = each %$data ) { print "$k => $v\n"; }
for ( @{$data->{secrets}} ) {
#    print $_->{name}."\n";
#    print $_->{value}."\n";
    retrieve_and_set_secrets($_->{name}, $_->{value});

}
