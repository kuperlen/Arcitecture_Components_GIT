#!/usr/bin/perl
#use strict;
use warnings FATAL => 'all';
use lib qw(..);

use JSON qw( );
use JSON::MaybeXS ();

sub SaveSecret {
    my ($sec_name, $sec_dest, $json_repl) = @_;
    print "Save new secret: $sec_name $json_repl to $sec_dest\n";
}

sub AddSecret {
    my ($sec_name, $sec_orig_loc) = @_;
    print "Add new secret: $sec_name from $sec_orig_loc\n";
}

sub RetrieveSecret{
    my ($sec_name, $sec_orig_loc, $sec_dest) = @_;
    print "DPE_URL ".$dpe_url."; Env_Name ".$env_name."; App_id ".$app_id."; Token ".$token."; secret-name ". $sec_name."; secret-value ".$sec_orig_loc."\n";
    # perform a secret fetch, if none returned, add the secret to DBE SM.
    my $command = "--insecure $dpe_url/secret/$app_id-$env_name-$sec_name -H \"Authorization: Bearer $token\"";
    print $command."\n";
    #my $result_text = `curl $command`;
    my $result_text = '{"ResponseMetadata": {"Status": "FAILURE", "Error": {"Type": "SecretNotFound"}, "RequestId": "ac7e53cd-cc58-43c9-b676-23b965042a72"}}';
    print $result_text."\n";
    my $json_repl = JSON->new->utf8->decode($result_text);
    my $resp_status = $json_repl->{ResponseMetadata}->{Status};
    print "Status: ".$resp_status."\n";
    if ($resp_status eq "FAILURE") {
        $status_type = $json_repl->{ResponseMetadata}->{Error}->{Type};
        if (($status_type eq "SecretNotFound") && ($retries < 3)) {
            $retries++;
            AddSecret ($sec_name, $sec_orig_loc);
            sleep 1;
            RetrieveSecret($sec_name, $sec_orig_loc, $sec_dest);
        } else {die("Failed to retrieve $sec_name from DPE_Secrets_Manager with status: $status_type $!\n");}
    } else {
        SaveSecret ($sec_name, $sec_dest, $json_repl);
    }
}

my $dpe_tokens = 'DPE-Tokens';
my $dpe_tokens_text = do {
    open(my $json_fh, "<:encoding(UTF-8)", $dpe_tokens)
        or die("Can't open $dpe_tokens\": $!\n");
    local $/;
    <$json_fh>
};
print $dpe_tokens_text."\n";
my $json_tokens = JSON->new;
my $data = $json_tokens->decode($dpe_tokens_text);

local $token = $data->{DPE_TOKEN};
local$app_id = $data->{DPE_APPID};
local $env_name = $data->{APP_ENV_NAME};
local $dpe_url = $data->{DPE_URL};
local $retries = 0;

my $secrets = $data->{secrets};

#while ( my ($k,$v) = each %$data ) { print "$k => $v\n"; }
for ( @{$data->{secrets}} ) {
#    print $_->{name}."\n";
#    print $_->{value}."\n";
    RetrieveSecret($_->{"name"}, $_->{"origin"}, $_->{"dest"});

}
